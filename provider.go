package scp02

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/skythen/apdu"
)

const (
	// KeyIDEnc is the ID of the Secure Channel encryption key (ENC).
	KeyIDEnc byte = 0x01
	// KeyIDMac is the ID of the Secure Channel message authentication code key (MAC).
	KeyIDMac byte = 0x02
	// KeyIDDek is the ID of the Data encryption key (DEK).
	KeyIDDek byte = 0x03
)

// Transmitter is the interface that transmits apdu.Capdu and returns apdu.Rapdu.
type Transmitter interface {
	Transmit(capdu apdu.Capdu) (apdu.Rapdu, error)
}

// SessionKeyProvider is the interface that provides access to the cryptographic operation for session key derivation.
type SessionKeyProvider interface {
	// ProvideSessionKey uses Triple DES encryption in CBC mode for the derivation of session keys with src containing
	// the derivation input Data (2B derivation constant | 2B sequence counter | 12B zero padding)
	// and dst being used for storing the encryption result.
	ProvideSessionKey(keyID byte, kvn byte, dst *[16]byte, src [16]byte) error
}

// SecurityLevel represents the security level options applicable for SCP02.
type SecurityLevel struct {
	CDEC bool // command decryption
	CMAC bool // command message authentication code
	RMAC bool // response message authentication code
}

// Byte encodes SecurityLevel on a byte.
func (level SecurityLevel) Byte() byte {
	b := byte(0x00)

	if level.CMAC {
		b += 0x01
	}

	if level.CDEC {
		b += 0x02
	}

	if level.RMAC {
		b += 0x10
	}

	return b
}

// Options represents implementation options of SCP02 that are encoded on the i-parameter.
// Other options such as R-MAC support, the initiation mode or number of base keys are not configured via Options
// but implicitly used e.g. by calling SessionProvider.InitiateChannelImplicit.
type Options struct {
	CMACOnUnmodifiedAPDU bool // true: C-MAC on unmodified APDU, false: C-MAC on modified APDU
	ICVEncryptionForCMAC bool // true: ICV encryption for C-MAC session, false: No ICV encryption
}

// ImplicitInitiationConfiguration is the configuration for the implicit initiation of a Secure Channel Session.
type ImplicitInitiationConfiguration struct {
	SecurityLevel    SecurityLevel
	Options          Options
	KeyVersionNumber uint8
	SequenceCounter  uint16
	Capdu            apdu.Capdu
	SelectedAid      []byte
}

// InitiateChannelImplicit uses implicit initiation to create a Secure Channel and returns a Session.
// The function will panic if the value of Transmitter is nil.
//
// Please note that C-DEC is not supported for implicit initiation and will not be used if it was
// provided with the Security Level in the SessionProvider Configuration.
//
// The Sequence Counter must be provided to derive the correct session keys. It is either implicitly known
// or can be retrieved with a GET DATA command. The AID of the application that is currently selected on
// the given channel is used for calculating the ICV for the first C-MAC (ICV MAC over AID).
//
// The first C-MAC is calculated on and appended to the given APDU which is then passed to
// Transmitter.Transmit.
func InitiateChannelImplicit(keyProvider SessionKeyProvider, transmitter Transmitter, config ImplicitInitiationConfiguration) (*Session, error) {
	if isNil(transmitter) {
		panic("value of inputTransmitter must not be nil")
	}

	if isNil(keyProvider) {
		panic("value of keyProvider must not be nil")
	}

	if config.SelectedAid != nil && len(config.SelectedAid) < 5 || len(config.SelectedAid) > 16 {
		return nil, errors.Errorf("invalid length of AID - must be in range 5-16 bytes, got: %d", len(config.SelectedAid))
	}

	channelID := getChannelID(config.Capdu.Cla)

	session := newSession(
		channelID,
		config.KeyVersionNumber,
		uint16ToBytes(config.SequenceCounter),
		config.SecurityLevel,
		config.Options)

	session.selectedAID = config.SelectedAid
	// C-DEC is not supported for implicit initiation
	session.securityLevel.CDEC = false

	session.sessionKeyProvider = keyProvider

	err := session.deriveCMAC()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive C-MAC session key")
	}

	// pad Data
	padded, err := Pad80(config.SelectedAid, 8, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to pad Data for CMAC calculation")
	}

	// calculate ICV Mac over AID
	err = desFinalTDESMac(&session.icv, padded, session.keys.cmac, scp02ZeroIV)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate CMAC with Single DES Final 3DES MAC")
	}

	wrapped, err := session.wrapWithSecurityLevel(config.Capdu, session.securityLevel, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap CAPDU")
	}

	wrapped.Cla = onLogicalChannel(channelID, wrapped.Cla)

	resp, err := transmitter.Transmit(wrapped)
	if err != nil {
		return nil, errors.New("failed to transmit CAPDU")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("failed to transmit command with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	session.incrementSequenceCounter()

	// derive DEK and R-MAC after sequence counter incrementation
	err = session.deriveDEK()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive DEK session key")
	}

	// since an R-MAC session can be initiated at any given time, derive R-MAC as well
	err = session.deriveRMAC()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive R-MAC session key")
	}

	// check for RMAC
	if session.securityLevel.RMAC {
		rmacSession := &RMACSession{
			channelID:   session.channelID,
			lastCommand: nil,
			ricv:        [8]byte{},
			rmac:        session.keys.rmac,
			lock:        sync.Mutex{},
		}

		copy(rmacSession.ricv[:], wrapped.Data[len(wrapped.Data)-8:])
		session.rmacSession = rmacSession
	}

	return session, nil
}

// ExplicitInitiationConfiguration is the configuration for the explicit initiation of a Secure Channel Session.
type ExplicitInitiationConfiguration struct {
	SecurityLevel    SecurityLevel
	Options          Options
	ChannelID        uint8
	KeyVersionNumber uint8
	HostChallenge    [8]byte
}

// InitiateChannelExplicit uses implicit initiation to create a Secure Channel and returns a Session.
// The function will panic if the value of Transmitter is nil.
//
// This function calls Transmitter.Transmit to transmit the INITIALIZE UPDATE and
// EXTERNAL AUTHENTICATE CAPDUs and receive the RAPDUs.
func InitiateChannelExplicit(transmitter Transmitter, keyProvider SessionKeyProvider, config ExplicitInitiationConfiguration) (*Session, error) {
	if isNil(transmitter) {
		panic("value of transmitter must not be nil")
	}

	if isNil(keyProvider) {
		panic("value of keyProvider must not be nil")
	}

	kvn := config.KeyVersionNumber

	capdu := initializeUpdate(kvn, config.HostChallenge)
	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.New("failed to transmit INITIALIZE UPDATE")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("INITIALIZE UPDATE failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	iur, err := parseSCP02InitializeUpdateResponse(resp.Data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid INITIALIZE UPDATE response")
	}

	session := newSession(config.ChannelID, config.KeyVersionNumber, iur.SequenceCounter, config.SecurityLevel, config.Options)
	session.sessionKeyProvider = keyProvider

	// derive session keys
	// ENC
	err = session.deriveENC()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive session ENC")
	}

	// CMAC
	err = session.deriveCMAC()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive C-MAC")
	}

	// RMAC
	err = session.deriveRMAC()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive R-MAC")
	}

	// DEK
	err = session.deriveDEK()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive session DEK")
	}

	cc, err := session.calculateCardCryptogram(config.HostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate card cryptogram on host")
	}

	// compare cryptogram presented by the card with own cryptogram
	if !bytes.Equal(cc[:], iur.CardCryptogram[:]) {
		return nil, fmt.Errorf("calculated card cryptogram on host %02X doesn't match the calculated cryptogram of the card %02X", cc, iur.CardCryptogram)
	}

	hc, err := session.calculateHostCryptogram(config.HostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate host cryptogram")
	}

	capdu, err = session.externalAuthenticate(hc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate EXTERNAL AUTHENTICATE command")
	}

	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err = transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.New("failed to transmit EXTERNAL AUTHENTICATE")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("EXTERNAL AUTHENTICATE failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	session.externalAuthenticateCMAC = capdu.Data[8:]
	session.incrementSequenceCounter()

	// check for RMAC
	if session.securityLevel.RMAC {
		rmacSession := &RMACSession{
			channelID:   session.channelID,
			lastCommand: nil,
			ricv:        [8]byte{},
			rmac:        session.keys.rmac,
			lock:        sync.Mutex{},
		}
		copy(rmacSession.ricv[:], session.externalAuthenticateCMAC)
		session.rmacSession = rmacSession
	}

	return session, nil
}

// ExplicitInitiationConfiguration is the configuration for the explicit initiation of a Secure Channel Session.
type RMACSessionConfiguration struct {
	ChannelID        uint8
	P1               byte
	Data             []byte
	KeyVersionNumber uint8
	SequenceCounter  uint16
}

// BeginRMACSession begins a R-MAC session and returns a RMACSession.
// It will panic if the value of Transmitter is nil.
// This function calls Transmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func BeginRMACSession(transmitter Transmitter, keyProvider SessionKeyProvider, config RMACSessionConfiguration) (*RMACSession, error) {
	if isNil(transmitter) {
		panic("value of transmitter must not be nil")
	}

	if isNil(keyProvider) {
		panic("value of keyProvider must not be nil")
	}

	rmac := [16]byte{}

	err := deriveSessionKey(
		&rmac,
		config.KeyVersionNumber,
		KeyIDMac,
		keyProvider,
		[2]byte{0x01, 0x02},
		uint16ToBytes(config.SequenceCounter))

	if err != nil {
		return nil, errors.Wrap(err, "failed to derive RMAC")
	}

	session := &RMACSession{}
	session.channelID = config.ChannelID

	capdu, err := beginRMACSession(config.P1, config.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create BEGIN R-MAC SESSION command")
	}

	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to transmit BEGIN R-MAC Session")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("BEGIN R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	return session, nil
}

func uint16ToBytes(u uint16) [2]byte {
	return [2]byte{(byte)(u>>8) & 0xFF, (byte)(u & 0xFF)}
}
