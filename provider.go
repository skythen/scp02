package scp02

import (
	"bytes"
	"crypto/des"
	"fmt"
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

// APDUTransmitter is the interface that transmits apdu.Capdu and returns apdu.Rapdu.
type APDUTransmitter interface {
	Transmit(capdu apdu.Capdu) (apdu.Rapdu, error)
}

// KeyProvider is the interface that provides access to static keys for SCP02.
type KeyProvider interface {
	// GetKey returns the TripleDESCBCEncrypter for a static DES key with the given key ID and key version number.
	// Key ID and key version number uniquely identify a key within the context of a Security Domain.
	// The AID of the Security Domain is implicitly known.
	GetKey(keyID byte, kvn byte) (TripleDESCBCEncrypter, error)
}

// TripleDESCBCEncrypter is the interface that provides access to the cryptographic operation for session key derivation.
type TripleDESCBCEncrypter interface {
	// Encrypt uses Triple DES in CBC mode for the derivation of session keys with src containing
	// the derivation input data (2B derivation constant | 2B sequence counter | 12B zero padding)
	// and dst being used for storing the encryption result.
	Encrypt(dst *[16]byte, src [16]byte) error
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

// SessionProvider is used for initiating a SCP02 Session or RMACSession.
type SessionProvider struct {
	keyProvider                   KeyProvider
	securityLevel                 SecurityLevel
	options                       Options
	useFirstAvailableSDKeyVersion bool
}

// NewSessionProvider returns a SessionProvider. It panics if the value of KeyProvider is nil.
func NewSessionProvider(provider KeyProvider, level SecurityLevel, options Options) *SessionProvider {
	if isNil(provider) {
		panic("value of provider must not be nil")
	}

	return &SessionProvider{
		keyProvider:   provider,
		securityLevel: level,
		options:       options,
	}
}

// InitiateChannelImplicit uses implicit initiation to create a Secure Channel and returns a Session.
// The function will panic if the value of APDUTransmitter is nil.
//
// Please note that C-DEC is not supported for implicit initiation and will not be used if it was
// provided with the Security Level in the SessionProvider Configuration.
//
// The Sequence Counter must be provided to derive the correct session keys. It is either implicitly known
// or can be retrieved with a GET DATA command. The AID of the application that is currently selected on
// the given channel is used for calculating the ICV for the first C-MAC (ICV MAC over AID).
//
// The first C-MAC is calculated on and appended to the given APDU which is then passed to
// APDUTransmitter.Transmit.
func (provider *SessionProvider) InitiateChannelImplicit(transmitter APDUTransmitter, keyVersionNumber byte, sequenceCounter [2]byte, capdu apdu.Capdu, selectedAid []byte) (*Session, error) {
	if isNil(transmitter) {
		panic("value of transmitter must not be nil")
	}

	if selectedAid != nil && len(selectedAid) < 5 || len(selectedAid) > 16 {
		return nil, errors.Errorf("invalid length of AID - must be in range 5-16 bytes, got: %d", len(selectedAid))
	}

	channelID := getChannelID(capdu.Cla)

	session := newSession(channelID, sequenceCounter, provider.securityLevel, provider.options)
	session.selectedAid = selectedAid
	// C-DEC is not supported for implicit initiation
	session.securityLevel.CDEC = false

	macProvider, err := provider.keyProvider.GetKey(KeyIDMac, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve provider for MAC key")
	}

	err = deriveSessionKey(&session.keys.cmac, macProvider, [2]byte{0x01, 0x01}, sequenceCounter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive C-MAC session key")
	}

	// pad data
	padded, err := Pad80(selectedAid, 8, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to pad data for CMAC calculation")
	}

	// calculate ICV Mac over AID
	err = desFinalTDESMac(&session.icv, padded, session.keys.cmac, scp02ZeroIV)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate CMAC with Single DES Final 3DES MAC")
	}

	wrapped, err := session.wrapWithSecurityLevel(capdu, provider.securityLevel, true)
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

	dekProvider, err := provider.keyProvider.GetKey(KeyIDDek, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve provider for DEK key")
	}

	// derive DEK and R-MAC after sequence counter incrementation
	err = session.deriveDEK(dekProvider)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive DEK session key")
	}

	// since an R-MAC session can be initiated at any given time, derive R-MAC as well
	err = session.deriveRMAC(session.macEncrypter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive R-MAC session key")
	}

	// check for RMAC
	if session.securityLevel.RMAC {
		rmacSession := &RMACSession{}
		copy(rmacSession.rmac[:], session.keys.rmac[:])
		copy(rmacSession.ricv[:], capdu.Data[len(capdu.Data)-8:])
		session.rmacSession = rmacSession
	}

	return session, nil
}

// InitiateChannelExplicit uses implicit initiation to create a Secure Channel and returns a Session.
// The function will panic if the value of APDUTransmitter is nil.
//
// This function calls APDUTransmitter.Transmit to transmit the INITIALIZE UPDATE and
// EXTERNAL AUTHENTICATE CAPDUs and receive the RAPDUs.
func (provider *SessionProvider) InitiateChannelExplicit(transmitter APDUTransmitter, channelID, keyVersionNumber byte, hostChallenge [8]byte) (*Session, error) {
	if isNil(transmitter) {
		panic("value of transmitter must not be nil")
	}

	kvn := keyVersionNumber

	capdu := initializeUpdate(kvn, hostChallenge)
	capdu.Cla = onLogicalChannel(channelID, capdu.Cla)

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

	encEncrypter, err := provider.keyProvider.GetKey(KeyIDEnc, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve encrypter for ENC key")
	}

	macEncrypter, err := provider.keyProvider.GetKey(KeyIDMac, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve encrypter for MAC key")
	}

	dekEncrypter, err := provider.keyProvider.GetKey(KeyIDDek, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve encrypter for DEK key")
	}

	session := newSession(channelID, iur.SequenceCounter, provider.securityLevel, provider.options)

	// derive session keys
	// ENC
	err = session.deriveENC(encEncrypter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive session ENC")
	}

	// CMAC
	err = session.deriveCMAC(macEncrypter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive C-MAC")
	}

	// RMAC
	err = session.deriveRMAC(macEncrypter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive R-MAC")
	}

	// DEK
	err = session.deriveDEK(dekEncrypter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive session DEK")
	}

	cc, err := session.calculateCardCryptogram(hostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate card cryptogram on host")
	}

	// compare cryptogram presented by the card with own cryptogram
	if !bytes.Equal(cc[:], iur.CardCryptogram[:]) {
		return nil, fmt.Errorf("calculated card cryptogram on host %02X doesn't match the calculated cryptogram of the card %02X", cc, iur.CardCryptogram)
	}

	hc, err := session.calculateHostCryptogram(hostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate host cryptogram")
	}

	capdu, err = session.externalAuthenticate(hc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate EXTERNAL AUTHENTICATE command")
	}

	capdu.Cla = onLogicalChannel(channelID, capdu.Cla)

	resp, err = transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.New("failed to transmit EXTERNAL AUTHENTICATE")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("EXTERNAL AUTHENTICATE failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	session.externalAuthenticateCmac = capdu.Data[8:]
	session.incrementSequenceCounter()

	// check for RMAC
	if session.securityLevel.RMAC {
		rmacSession := &RMACSession{}
		copy(rmacSession.rmac[:], session.keys.rmac[:])
		copy(rmacSession.ricv[:], session.externalAuthenticateCmac)
		session.rmacSession = rmacSession
	}

	return session, nil
}

// BeginRMACSession begins a R-MAC session and returns a RMACSession.
// The function will panic if the value of APDUTransmitter is nil.
//
// This function calls APDUTransmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func (provider *SessionProvider) BeginRMACSession(transmitter APDUTransmitter, channelID, p1 byte, data []byte, keyVersionNumber byte, sequenceCounter [2]byte) (*RMACSession, error) {
	if isNil(transmitter) {
		panic("value of transmitter must not be nil")
	}

	macEncrypter, err := provider.keyProvider.GetKey(KeyIDMac, keyVersionNumber)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve encrypter for MAC key")
	}

	sessionRmac := [16]byte{}

	err = deriveSessionKey(&sessionRmac, macEncrypter, [2]byte{0x01, 0x02}, sequenceCounter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive RMAC")
	}

	tdes := resizeDoubleDESToTDES(sessionRmac)

	session := &RMACSession{}
	session.channelID = channelID

	session.rmacTDESCipher, err = des.NewTripleDESCipher(tdes[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TripleDESCipher from RMAC")
	}

	capdu, err := beginRMACSession(p1, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create BEGIN R-MAC SESSION command")
	}

	capdu.Cla = onLogicalChannel(channelID, capdu.Cla)

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to transmit BEGIN R-MAC Session")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("BEGIN R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	return session, nil
}
