package scp02

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
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
	// ProvideSessionKey uses the static key with the given key ID and key version number with
	// Triple DES encryption in CBC mode for the derivation of a session key.
	// diversificationData may be present to provide data for the derivation of card static keys.
	// src contains the derivation input Data (2B derivation constant | 2B sequence counter | 12B zero padding)
	// and dst is used for storing the encryption result.
	ProvideSessionKey(keyID byte, kvn byte, diversificationData []byte, dst *[16]byte, src [16]byte) error
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
// but implicitly used e.g. by calling InitiateChannelImplicit or InitiateChannelExplicit.
type Options struct {
	CMACOnUnmodifiedAPDU bool // true: C-MAC on unmodified APDU, false: C-MAC on modified APDU
	ICVEncryptionForCMAC bool // true: ICV encryption for C-MAC session, false: No ICV encryption
}

// ImplicitInitiationConfiguration is the configuration for the implicit initiation of a Secure Channel Session.
type ImplicitInitiationConfiguration struct {
	SecurityLevel       SecurityLevel // security level that shall be used for the session
	Options             Options       // i-parameter options
	KeyVersionNumber    uint8         // key version number of the key(s) to use
	SequenceCounter     uint16        // current value of the sequence counter
	Capdu               apdu.Capdu    // command APDU on which the initial C-MAC shall be calculated
	SelectedAid         []byte        // AID of the currently selected application
	DiversificationData []byte        // key diversification data
}

// InitiateChannelImplicit uses implicit initiation to create a Secure Channel and returns a Session.
// Please note that security level C-DEC is not supported for implicit initiation and will lead to errors
// if used.
//
// The Sequence Counter must be provided to derive the correct session keys. It is either implicitly known
// or can be retrieved with a GET DATA command. The AID of the application that is currently selected on
// the given channel is used for calculating the ICV for the first C-MAC (ICV MAC over AID).
//
// The first C-MAC is calculated on and appended to the given APDU which is then passed to Transmitter.Transmit.
func InitiateChannelImplicit(config ImplicitInitiationConfiguration, transmitter Transmitter, keyProvider SessionKeyProvider) (*Session, error) {
	if len(config.SelectedAid) < 5 || len(config.SelectedAid) > 16 {
		return nil, errors.Errorf("invalid length of AID - must be in range 5-16 bytes, got: %d", len(config.SelectedAid))
	}

	channelID := channelIDFromCLA(config.Capdu.Cla)

	session := newSession(
		channelID,
		config.KeyVersionNumber,
		uint16ToBytes(config.SequenceCounter),
		config.SecurityLevel,
		config.Options)

	session.selectedAID = config.SelectedAid
	session.keyProvider = keyProvider

	err := session.deriveCMAC()
	if err != nil {
		return nil, errors.Wrap(err, "derive C-MAC session key")
	}

	// pad Data
	padded, err := Pad80(config.SelectedAid, 8, true)
	if err != nil {
		return nil, errors.Wrap(err, "pad Data for C-MAC calculation")
	}

	// calculate ICV Mac over AID
	err = desFinalTDESMac(&session.icv, padded, session.keys.cmac, scp02ZeroIV)
	if err != nil {
		return nil, errors.Wrap(err, "calculate C-MAC with Single DES Final 3DES MAC")
	}

	wrappedCmd, err := session.wrapWithSecurityLevel(config.Capdu, session.securityLevel, true)
	if err != nil {
		return nil, errors.Wrap(err, "wrap CAPDU")
	}

	wrappedCmd.Cla = onLogicalChannel(channelID, wrappedCmd.Cla)

	resp, err := transmitter.Transmit(wrappedCmd)
	if err != nil {
		return nil, errors.New("transmit CAPDU")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("transmit command returned non-success SW: %02X%02X", resp.SW1, resp.SW2)
	}

	session.incrementSequenceCounter()

	// derive DEK and R-MAC after sequence counter incrementation
	err = session.deriveSDEK()
	if err != nil {
		return nil, errors.Wrap(err, "derive DEK session key")
	}

	// since an R-MAC session can be initiated at any given time, derive R-MAC as well
	err = session.deriveRMAC()
	if err != nil {
		return nil, errors.Wrap(err, "derive R-MAC session key")
	}

	// check for R-MAC
	if session.securityLevel.RMAC {
		rmacSession := &RMACSession{
			channelID:   session.channelID,
			lastCommand: nil,
			ricv:        [8]byte{},
			rmac:        session.keys.rmac,
			lock:        sync.Mutex{},
		}

		copy(rmacSession.ricv[:], wrappedCmd.Data[len(wrappedCmd.Data)-8:])
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
// This function calls Transmitter.Transmit to transmit the INITIALIZE UPDATE and
// EXTERNAL AUTHENTICATE CAPDUs and receive the RAPDUs.
func InitiateChannelExplicit(config ExplicitInitiationConfiguration, transmitter Transmitter, keyProvider SessionKeyProvider) (*Session, error) {
	kvn := config.KeyVersionNumber

	capdu := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x50,
		P1:   kvn,
		P2:   0x00,
		Data: config.HostChallenge[:],
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.New("transmit INITIALIZE UPDATE")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("INITIALIZE UPDATE returned non-success SW: %02X%02X", resp.SW1, resp.SW2)
	}

	iur, err := parseInitializeUpdateResponse(resp.Data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid INITIALIZE UPDATE response")
	}

	session := newSession(config.ChannelID, config.KeyVersionNumber, iur.SequenceCounter, config.SecurityLevel, config.Options)
	session.keyProvider = keyProvider
	session.diversificationData = iur.KeyDiversificationData[:]

	// derive session keys
	// S-ENC
	err = session.deriveSENC()
	if err != nil {
		return nil, errors.Wrap(err, "derive session ENC")
	}

	// C-MAC
	err = session.deriveCMAC()
	if err != nil {
		return nil, errors.Wrap(err, "derive C-MAC")
	}

	// R-MAC
	err = session.deriveRMAC()
	if err != nil {
		return nil, errors.Wrap(err, "derive R-MAC")
	}

	// S-DEK
	err = session.deriveSDEK()
	if err != nil {
		return nil, errors.Wrap(err, "derive session DEK")
	}

	cc, err := session.calculateCardCryptogram(config.HostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "calculate card cryptogram on host")
	}

	// compare cryptogram presented by the card with own cryptogram
	if !bytes.Equal(cc[:], iur.CardCryptogram[:]) {
		return nil, fmt.Errorf("calculated card cryptogram on host %02X doesn't match the calculated cryptogram of the card %02X", cc, iur.CardCryptogram)
	}

	hc, err := session.calculateHostCryptogram(config.HostChallenge, iur.SequenceCounter, iur.CardChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "calculate host cryptogram")
	}

	capdu, err = session.externalAuthenticate(hc)
	if err != nil {
		return nil, errors.Wrap(err, "generate EXTERNAL AUTHENTICATE command")
	}

	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err = transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.New("transmit EXTERNAL AUTHENTICATE")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("EXTERNAL AUTHENTICATE returned non-success SW: %02X%02X", resp.SW1, resp.SW2)
	}

	session.externalAuthenticateCMAC = capdu.Data[8:]
	session.incrementSequenceCounter()

	// check for R-MAC
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

// RMACSessionConfiguration is the configuration for the initiation of an RMACSession.
type RMACSessionConfiguration struct {
	ChannelID           uint8
	P1                  byte
	Data                []byte
	KeyVersionNumber    uint8
	SequenceCounter     uint16
	diversificationData []byte
}

// BeginRMACSession begins an R-MAC session and returns RMACSession.
// This function calls Transmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func BeginRMACSession(config RMACSessionConfiguration, transmitter Transmitter, keyProvider SessionKeyProvider) (*RMACSession, error) {
	rmac := [16]byte{}

	err := deriveSessionKey(
		&rmac,
		KeyIDMac,
		config.KeyVersionNumber,
		config.diversificationData,
		keyProvider,
		[2]byte{0x01, 0x02},
		uint16ToBytes(config.SequenceCounter))

	if err != nil {
		return nil, errors.Wrap(err, "derive R-MAC")
	}

	session := &RMACSession{}
	session.channelID = config.ChannelID

	capdu, err := beginRMACSession(config.P1, config.Data)
	if err != nil {
		return nil, errors.Wrap(err, "create BEGIN R-MAC SESSION command")
	}

	capdu.Cla = onLogicalChannel(config.ChannelID, capdu.Cla)

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.Wrap(err, "transmit BEGIN R-MAC Session")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("BEGIN R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	return session, nil
}

func uint16ToBytes(u uint16) [2]byte {
	return [2]byte{(byte)(u>>8) & 0xFF, (byte)(u & 0xFF)}
}

const (
	BeginRMACSessionP1RMAC              byte = 0x10
	BeginRMACSessionP1NoSecureMessaging byte = 0x00
	EndRMACSessionP2EndAndReturnRMAC    byte = 0x03
	EndRMACSessionP2ReturnRMAC          byte = 0x01
	claGP                               byte = 0x80
)

var scp02ZeroIV = [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Session is a SCP02 secure channel session.
type Session struct {
	channelID                uint8
	sequenceCounter          [2]byte
	securityLevel            SecurityLevel
	options                  Options
	keyProvider              SessionKeyProvider
	keys                     sessionKeys
	icv                      [8]byte
	externalAuthenticateCMAC []byte
	diversificationData      []byte
	selectedAID              []byte
	rmacSession              *RMACSession
	lock                     sync.Mutex
}

func newSession(channelID uint8, kvn uint8, sequenceCounter [2]byte, securityLevel SecurityLevel, options Options) *Session {
	return &Session{
		channelID:                channelID,
		sequenceCounter:          sequenceCounter,
		options:                  options,
		securityLevel:            securityLevel,
		keyProvider:              nil,
		keys:                     sessionKeys{kvn: kvn},
		icv:                      [8]byte{},
		externalAuthenticateCMAC: nil,
		selectedAID:              nil,
		rmacSession:              nil,
		lock:                     sync.Mutex{},
	}
}

// SecurityLevel returns the Security Level of the Session.
func (session *Session) SecurityLevel() SecurityLevel {
	return session.securityLevel
}

// ChannelID returns the ID of the channel the Session is active on.
func (session *Session) ChannelID() uint8 {
	return session.channelID
}

// SequenceCounter returns the session's value of the Sequence Counter.
func (session *Session) SequenceCounter() uint16 {
	return binary.BigEndian.Uint16(session.sequenceCounter[:])
}

// Wrap takes an apdu.Capdu and applies C-MAC and encryption according to the Session's SecurityLevel and returns the wrapped apdu.Capdu.
func (session *Session) Wrap(capdu apdu.Capdu) (apdu.Capdu, error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	return session.wrapWithSecurityLevel(capdu, session.securityLevel, false)
}

func (session *Session) wrapWithSecurityLevel(capdu apdu.Capdu, level SecurityLevel, firstCmd bool) (apdu.Capdu, error) {
	var (
		cmac [8]byte
		err  error
	)

	if level.RMAC {
		// check for active R-MAC session and update last command
		if session.rmacSession != nil {
			session.rmacSession.UpdateLastCommand(capdu)
		}
	}

	if level.CMAC {
		// check if wrapped capdu length would exceed maximum allowed length
		if len(capdu.Data)+8 > 255 {
			return apdu.Capdu{}, errors.New("capdu length with C-MAC exceeds maximum allowed length ")
		}

		// ICV encryption for C-MAC
		if !firstCmd && session.options.ICVEncryptionForCMAC {
			encICV := make([]byte, len(session.icv))

			err = desECBEncrypt(encICV, session.icv[:], session.keys.cmacCipher)
			if err != nil {
				return apdu.Capdu{}, errors.Wrap(err, "encrypt ICV with DES ECB")
			}

			// copy the value of the encrypted icv to the session icv
			copy(session.icv[:], encICV)
		}

		cmac, err = session.calculateCMAC(capdu)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "calculate C-MAC")
		}

		copy(session.icv[:], cmac[:])
	}

	// command encryption
	if level.CDEC && len(capdu.Data) != 0 {
		encData, err := session.encryptDataField(capdu.Data)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "encrypt command Data field")
		}

		capdu.Data = encData
	}

	// append C-MAC after encryption
	if level.CMAC {
		capdu.Data = append(capdu.Data, cmac[:]...)
	}

	if level.CMAC || level.CDEC {
		if (capdu.Cla & byte(0x04)) != 0x04 {
			capdu.Cla += 0x04
		}
	}

	return capdu, nil
}

func (session *Session) calculateCMAC(capdu apdu.Capdu) (cmac [8]byte, err error) {
	// any indication of logical channel number shall be removed from the class byte
	if capdu.Cla&byte(0x4F) != 0x00 {
		capdu.Cla -= 0x4F
	}

	// remove le for C-MAC calculation
	capdu.Ne = 0

	bCapdu := capdu.Bytes()

	// C-MAC on modified APDU
	if !session.options.CMACOnUnmodifiedAPDU {
		// the length of the command message (Lc) shall be incremented by 8
		if len(bCapdu) < apdu.OffsetLcStandard+1 {
			bCapdu = append(bCapdu, 0x08)
		} else {
			bCapdu[apdu.OffsetLcStandard] += 0x08
		}

		// class byte shall have bit 4 set to 0
		if bCapdu[0]&0x08 != 0x00 {
			bCapdu[0] -= 0x08
		}
		// set bit 3 to indicate GlobalPlatform proprietary secure messaging
		if (bCapdu[0] & byte(0x04)) != 0x04 {
			bCapdu[0] += 0x04
		}
	}

	// calculate C-MAC
	bCapdu, err = Pad80(bCapdu, 8, true)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "pad Data for C-MAC calculation")
	}

	err = desFinalTDESMac(&cmac, bCapdu, session.keys.cmac, session.icv)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "calculate C-MAC with Single DES Final 3DES MAC")
	}

	return cmac, nil
}

func (session *Session) encryptDataField(data []byte) (encData []byte, err error) {
	data, err = Pad80(data, 8, true)
	if err != nil {
		return nil, errors.Wrap(err, "pad Data for encryption")
	}

	// use zero iv for encryption
	tdesCBCDec := cipher.NewCBCEncrypter(session.keys.encTDESCipher, scp02ZeroIV[:])
	result := make([]byte, len(data))
	tdesCBCDec.CryptBlocks(result, data)

	return result, nil
}

// Unwrap takes an apdu.Rapdu and verifies the R-MAC if an R-MAC session was started with Session and returns the unwrapped apdu.Rapdu.
func (session *Session) Unwrap(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	if session.rmacSession != nil {
		return session.rmacSession.unwrapWithSecurityLevel(rapdu)
	}

	return rapdu, nil
}

// EncryptWithSDEK uses Triple DES in ECB mode for encrypting the given Data with the session DEK.
// The length of src and dst must be a multiple of 8. If padding is required, it must be applied before calling the function.
func (session *Session) EncryptWithSDEK(dst []byte, src []byte) error {
	err := tripleDESEcbEncrypt(dst, src, session.keys.dekTDES)
	if err != nil {
		return errors.Wrap(err, "encrypt Data with TripleDES ECB")
	}

	return nil
}

// MaximumCommandPayloadLength returns the maximum length of payload for the Data field of CAPDUs that are
// transmitted during the session. The length depends on the Session's SecurityLevel.
func (session *Session) MaximumCommandPayloadLength() int {
	d := 255
	if session.securityLevel.CMAC {
		d -= 8
	}

	if session.securityLevel.CDEC {
		d -= 8
	}

	return d
}

type keyInformation struct {
	version byte
	scpID   byte
}

func parseInitializeUpdateResponse(b []byte) (*initializeUpdateResponse, error) {
	if len(b) != 28 {
		return nil, fmt.Errorf("INITIALIZE UPDATE response must be 28 bytes long, got %d", len(b))
	}

	var (
		divData    [10]byte
		counter    [2]byte
		challenge  [6]byte
		cryptogram [8]byte
	)

	_ = copy(divData[:], b[:10])
	_ = copy(counter[:], b[12:14])

	keyInfo := keyInformation{version: b[10], scpID: b[11]}

	if keyInfo.scpID != 0x02 {
		return nil, fmt.Errorf("scp ID must be 02, got %d", keyInfo.scpID)
	}

	_ = copy(challenge[:], b[14:20])
	_ = copy(cryptogram[:], b[20:])

	return &initializeUpdateResponse{
		KeyDiversificationData: divData,
		KeyInformation:         keyInfo,
		CardChallenge:          challenge,
		CardCryptogram:         cryptogram,
		SequenceCounter:        counter,
	}, nil
}

type initializeUpdateResponse struct {
	KeyDiversificationData [10]byte       // key diversification Data is Data typically used by a backend system to derive the card static keys.
	KeyInformation         keyInformation // key information includes the version Number and the Secure Channel Protocol identifier
	SequenceCounter        [2]byte        // current value of the sequence counter used for session key derivation
	CardChallenge          [6]byte        // random number generated by the card
	CardCryptogram         [8]byte        // authentication cryptogram generated by the card
}

func (session *Session) externalAuthenticate(hostCryptogram [8]byte) (apdu.Capdu, error) {
	authCmd := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x82,
		P1:   session.securityLevel.Byte(),
		P2:   0x00,
		Data: hostCryptogram[:],
		Ne:   0,
	}

	wrappedAuthCmd, err := session.wrapWithSecurityLevel(authCmd, SecurityLevel{CMAC: true}, true)
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "wrap EXTERNAL AUTHENTICATE command")
	}

	return wrappedAuthCmd, nil
}

func (session *Session) calculateCardCryptogram(hc [8]byte, seqCounter [2]byte, cc [6]byte) ([8]byte, error) {
	ccInput := make([]byte, 0, 16)
	ccInput = append(ccInput, hc[:]...)
	ccInput = append(ccInput, seqCounter[:]...)
	ccInput = append(ccInput, cc[:]...)

	data, err := Pad80(ccInput, 24, false)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "pad Data for 3DES MAC")
	}

	var cryptogram [8]byte

	err = fullTDESMac(&cryptogram, data, session.keys.encTDESCipher, scp02ZeroIV)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "calculate 3DES MAC")
	}

	return cryptogram, nil
}

func (session *Session) calculateHostCryptogram(hc [8]byte, seqCounter [2]byte, cc [6]byte) ([8]byte, error) {
	hcInput := make([]byte, 0, 16)
	hcInput = append(hcInput, seqCounter[:]...)
	hcInput = append(hcInput, cc[:]...)
	hcInput = append(hcInput, hc[:]...)

	data, err := Pad80(hcInput, len(hcInput)+8, false)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "pad Data for 3DES MAC")
	}

	var cryptogram [8]byte

	err = fullTDESMac(&cryptogram, data, session.keys.encTDESCipher, scp02ZeroIV)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "calculate 3DES MAC")
	}

	return cryptogram, nil
}

type sessionKeys struct {
	kvn           uint8
	cmac          [16]byte
	rmac          [16]byte
	dekTDES       [24]byte
	cmacCipher    cipher.Block
	encTDESCipher cipher.Block
}

func deriveSessionKey(dst *[16]byte, keyID byte, kvn byte, diversificationData []byte, provider SessionKeyProvider, derivationConstant, sequenceCounter [2]byte) error {
	var derivationData [16]byte

	copy(derivationData[:], append(derivationConstant[:], sequenceCounter[:]...))

	err := provider.ProvideSessionKey(keyID, kvn, diversificationData, dst, derivationData)
	if err != nil {
		return errors.Wrap(err, "provide session key")
	}

	return nil
}

func (session *Session) deriveCMAC() error {
	var (
		derivedKey [16]byte
	)

	err := deriveSessionKey(&derivedKey, KeyIDMac, session.keys.kvn, session.diversificationData, session.keyProvider, [2]byte{0x01, 0x01}, session.sequenceCounter)
	if err != nil {
		return err
	}

	copy(session.keys.cmac[:], derivedKey[:])

	session.keys.cmacCipher, err = des.NewCipher(derivedKey[:8])
	if err != nil {
		return errors.Wrap(err, "create DES cipher from C-MAC")
	}

	return nil
}

func (session *Session) deriveRMAC() error {
	var derivedKey [16]byte

	err := deriveSessionKey(&derivedKey, KeyIDMac, session.keys.kvn, session.diversificationData, session.keyProvider, [2]byte{0x01, 0x02}, session.sequenceCounter)
	if err != nil {
		return err
	}

	copy(session.keys.rmac[:], derivedKey[:])

	return nil
}

func (session *Session) deriveSDEK() error {
	var (
		derivedKey [16]byte
		tdesKey    [24]byte
	)

	err := deriveSessionKey(&derivedKey, KeyIDDek, session.keys.kvn, session.diversificationData, session.keyProvider, [2]byte{0x01, 0x81}, session.sequenceCounter)
	if err != nil {
		return err
	}

	tdesKey = resizeDoubleDESToTDES(derivedKey)

	copy(session.keys.dekTDES[:], tdesKey[:])

	return nil
}

func (session *Session) deriveSENC() error {
	var (
		derivedKey [16]byte
		tdesKey    [24]byte
	)

	err := deriveSessionKey(&derivedKey, KeyIDEnc, session.keys.kvn, session.diversificationData, session.keyProvider, [2]byte{0x01, 0x82}, session.sequenceCounter)
	if err != nil {
		return err
	}

	tdesKey = resizeDoubleDESToTDES(derivedKey)

	session.keys.encTDESCipher, err = des.NewTripleDESCipher(tdesKey[:])
	if err != nil {
		return errors.Wrap(err, "create TripleDES cipher from S-ENC")
	}

	return nil
}

// incrementSequenceCounter increments the Session sequenceCounter by 1.
func (session *Session) incrementSequenceCounter() {
	session.lock.Lock()
	defer session.lock.Unlock()

	if session.sequenceCounter[0] != 0x00 {
		if session.sequenceCounter[1] < 0xFF {
			session.sequenceCounter[1] += 0x01
		} else {
			session.sequenceCounter[1] = 0x00
			session.sequenceCounter[0] += 0x01
		}
	}

	session.sequenceCounter[1] += 0x01
}

// BeginRMACSession starts a R-MAC session. Data is used to specify the Data field of the BEGIN R-MAC SESSION command.
// This function calls SessionKeyProvider.ProvideSessionKey on the sessionKeyProvider for the MAC key, that was provided when creating Session, in order to derive the R-MAC key
// and calls Transmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func (session *Session) BeginRMACSession(transmitter Transmitter, data []byte) error {
	session.lock.Lock()
	defer session.lock.Unlock()

	rmac := [16]byte{}

	err := deriveSessionKey(&rmac, KeyIDMac, session.keys.kvn, session.diversificationData, session.keyProvider, [2]byte{0x01, 0x02}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "derive R-MAC")
	}

	session.keys.rmac = rmac

	rmacSession := &RMACSession{}

	beginCmd, err := beginRMACSession(BeginRMACSessionP1RMAC, data)
	if err != nil {
		return errors.Wrap(err, "create BEGIN R-MAC SESSION command")
	}

	wrappedBeginCmd, err := session.wrapWithSecurityLevel(beginCmd, session.securityLevel, false)
	if err != nil {
		return errors.Wrap(err, "wrap BEGIN R-MAC SESSION command")
	}

	wrappedBeginCmd.Cla = onLogicalChannel(session.channelID, wrappedBeginCmd.Cla)

	resp, err := transmitter.Transmit(wrappedBeginCmd)
	if err != nil {
		return errors.Wrap(err, "transmit BEGIN R-MAC Session")
	}

	if !resp.IsSuccess() {
		return errors.Errorf("BEGIN R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	if session.selectedAID == nil {
		copy(rmacSession.ricv[:], session.externalAuthenticateCMAC)
	} else {
		// pad Data
		padded, err := Pad80(session.selectedAID, 8, true)
		if err != nil {
			return errors.Wrap(err, "pad Data for C-MAC calculation")
		}

		// calculate the C-MAC
		err = desFinalTDESMac(&rmacSession.ricv, padded, session.keys.rmac, scp02ZeroIV)
		if err != nil {
			return errors.Wrap(err, "calculate C-MAC with Single DES Final 3DES MAC")
		}
	}

	session.rmacSession = rmacSession

	return nil
}

// EndRMACSession ends an R-MAC session and/or retrieves the current R-MAC value depending on the value of endSession.
// This function calls Transmitter.Transmit to transmit the END R-MAC SESSION CAPDU and receive the RAPDU.
func (session *Session) EndRMACSession(transmitter Transmitter, endSession bool) (rmac []byte, err error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	if session.rmacSession == nil {
		return nil, errors.New("session has no active R-MAC session")
	}

	var p2 byte

	if endSession {
		p2 = EndRMACSessionP2EndAndReturnRMAC
	} else {
		p2 = EndRMACSessionP2ReturnRMAC
	}

	endCmd := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x78,
		P1:   0x00,
		P2:   p2,
		Data: nil,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	wrappedEndCmd, err := session.wrapWithSecurityLevel(endCmd, session.securityLevel, false)
	if err != nil {
		return nil, errors.Wrap(err, "wrap END R-MAC SESSION command")
	}

	wrappedEndCmd.Cla = onLogicalChannel(session.channelID, wrappedEndCmd.Cla)

	resp, err := transmitter.Transmit(wrappedEndCmd)
	if err != nil {
		return nil, errors.Wrap(err, "transmit END R-MAC Session")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("END R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	rmac = resp.Data

	if endSession {
		session.rmacSession.lastCommand = nil
	}

	return rmac, nil
}

func beginRMACSession(p1 byte, data []byte) (apdu.Capdu, error) {
	if len(data) == 0x00 || len(data) > 25 || len(data[1:]) != int(data[0]) {
		return apdu.Capdu{}, errors.New("invalid length of Data for BEGIN R-MAC Session " +
			"- must be in range 1-25 bytes with first byte indicating the Data length")
	}

	if p1 != BeginRMACSessionP1RMAC && p1 != BeginRMACSessionP1NoSecureMessaging {
		return apdu.Capdu{}, errors.New("invalid value for P1")
	}

	return apdu.Capdu{
		Cla:  claGP,
		Ins:  0x7A,
		P1:   p1,
		P2:   0x00,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// RMACSession is a SCP02 R-MAC session.
type RMACSession struct {
	channelID   byte
	lastCommand []byte
	ricv        [8]byte
	rmac        [16]byte
	lock        sync.Mutex
}

// End ends an R-MAC session and/or retrieves the current R-MAC value depending on the value of endSession.
// This function calls Transmitter.Transmit to transmit the END R-MAC SESSION CAPDU and receive the RAPDU.
func (rmacSession *RMACSession) End(transmitter Transmitter, endSession bool) ([]byte, error) {
	rmacSession.lock.Lock()
	defer rmacSession.lock.Unlock()

	var p2 byte

	if endSession {
		p2 = EndRMACSessionP2EndAndReturnRMAC
	} else {
		p2 = EndRMACSessionP2ReturnRMAC
	}

	endCmd := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x78,
		P1:   0x00,
		P2:   p2,
		Data: nil,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	resp, err := transmitter.Transmit(endCmd)
	if err != nil {
		return nil, errors.Wrap(err, "transmit END R-MAC Session")
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("END R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	if endSession {
		rmacSession.lastCommand = nil
		rmacSession.ricv = [8]byte{}
	}

	return resp.Data, nil
}

// UpdateLastCommand updates the last command that was sent during the R-MAC session
// which is required for the calculation and verification of the R-MAC.
func (rmacSession *RMACSession) UpdateLastCommand(capdu apdu.Capdu) {
	rmacSession.lock.Lock()
	defer rmacSession.lock.Unlock()

	var lastCmd []byte

	if capdu.Cla&byte(0x07) != 0x00 {
		lastCmd = append(lastCmd, capdu.Cla-0x07)
	}

	lastCmd = append(lastCmd, capdu.Cla)
	lastCmd = append(lastCmd, capdu.Ins)
	lastCmd = append(lastCmd, capdu.P1)
	lastCmd = append(lastCmd, capdu.P2)

	//  in the case of a case 1 or case 2 command, Lc is always present and set to zero
	if capdu.Data != nil {
		lastCmd = append(lastCmd, capdu.Lc()...)
		lastCmd = append(lastCmd, capdu.Data...)
	} else {
		lastCmd = append(lastCmd, 0x00)
	}

	rmacSession.lastCommand = lastCmd
}

func (rmacSession *RMACSession) unwrapWithSecurityLevel(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	rmacSession.lock.Lock()
	defer rmacSession.lock.Unlock()

	if len(rapdu.Data) < 8 {
		return apdu.Rapdu{}, fmt.Errorf("response length must be at least 8 bytes long, got %d", len(rapdu.Data))
	}

	if rmacSession.lastCommand == nil {
		return apdu.Rapdu{}, errors.New("no last command for R-MAC calculation found - did you forget to call UpdateLastCommand?")
	}

	// get response Data without R-MAC
	responseData := rapdu.Data[:len(rapdu.Data)-8]

	lenRMACInput := len(rmacSession.lastCommand) + len(responseData) + 3

	rmacInput := make([]byte, 0, lenRMACInput)
	rmacInput = append(rmacInput, rmacSession.lastCommand...)

	if rapdu.IsSuccess() || rapdu.IsWarning() {
		if rapdu.Data != nil {
			rmacInput = append(rmacInput, byte(len(responseData)%apdu.MaxLenResponseDataStandard))
			rmacInput = append(rmacInput, responseData...)
		} else {
			rmacInput = append(rmacInput, 0x00)
		}
	} else if rapdu.IsError() {
		rmacInput = append(rmacInput, 0x00)
	}

	rmacInput = append(rmacInput, rapdu.SW1)
	rmacInput = append(rmacInput, rapdu.SW2)

	var err error

	// pad input
	rmacInput, err = Pad80(rmacInput, 8, true)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "pad Data for R-MAC calculation")
	}

	var calculatedRMAC [8]byte

	err = desFinalTDESMac(&calculatedRMAC, rmacInput, rmacSession.rmac, rmacSession.ricv)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "calculate R-MAC with Single DES with Final 3DES Mac")
	}

	receivedRMAC := rapdu.Data[len(rapdu.Data)-8:]

	if !bytes.Equal(calculatedRMAC[:], receivedRMAC) {
		return apdu.Rapdu{}, fmt.Errorf("calculated R-MAC on host (%02X) doesn't match the calculated R-MAC of the card (%02X)", calculatedRMAC[:], receivedRMAC)
	}

	// R-MAC is used as ICV for next calculation
	copy(rmacSession.ricv[:], calculatedRMAC[:])

	rapdu.Data = responseData

	return rapdu, nil
}
