package scp02

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"github.com/skythen/apdu"
	"sync"
)

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
	channelID                byte
	sequenceCounter          [2]byte
	options                  Options
	securityLevel            SecurityLevel
	macEncrypter             TripleDESCBCEncrypter
	keys                     sessionKeys
	icv                      [8]byte
	externalAuthenticateCmac []byte
	selectedAid              []byte
	rmacSession              *RMACSession
	lock                     sync.Mutex
}

func newSession(channelID byte, sequenceCounter [2]byte, securityLevel SecurityLevel, options Options) *Session {
	return &Session{
		channelID:                channelID,
		sequenceCounter:          sequenceCounter,
		options:                  options,
		securityLevel:            securityLevel,
		macEncrypter:             nil,
		keys:                     sessionKeys{},
		icv:                      [8]byte{},
		externalAuthenticateCmac: nil,
		selectedAid:              nil,
		rmacSession:              nil,
		lock:                     sync.Mutex{},
	}
}

// SecurityLevel returns the Security Level of the Session.
func (session *Session) SecurityLevel() SecurityLevel {
	return session.securityLevel
}

// SecurityLevel returns the ID of the channel the Session is active on.
func (session *Session) ChannelID() byte {
	return session.channelID
}

// SequenceCounter returns the session's value of the Sequence Counter.
func (session *Session) SequenceCounter() [2]byte {
	return session.sequenceCounter
}

// Wrap takes an apdu.Capdu and applies C-MAC and encryption according to the Session's SecurityLevel and returns the wrapped apdu.Capdu.
func (session *Session) Wrap(capdu apdu.Capdu) (apdu.Capdu, error) {
	return session.wrapWithSecurityLevel(capdu, session.securityLevel, false)
}

func (session *Session) wrapWithSecurityLevel(capdu apdu.Capdu, level SecurityLevel, firstCmd bool) (apdu.Capdu, error) {
	session.lock.Lock()
	defer session.lock.Unlock()

	var (
		cmac    [8]byte
		wrapped apdu.Capdu
		err     error
	)

	if level.RMAC {
		// check for active RMAC session and update last command
		if session.rmacSession != nil {
			session.rmacSession.UpdateLastCommand(capdu)
		}
	}

	// if no crypto needs to be applied, return the capdu as it is
	if !level.CDEC && !level.CMAC {
		return capdu, nil
	}

	if level.CMAC {
		// check if wrapped capdu length would exceed maximum allowed length
		if len(capdu.Data)+8 > 255 {
			return apdu.Capdu{}, errors.New("capdu length with CMAC exceeds maximum allowed length ")
		}

		// create a copy of the CAPDU to wrap
		err = copier.Copy(&wrapped, &capdu)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "failed to copy capdu")
		}

		// ICV encryption for C-MAC
		if !firstCmd && session.options.ICVEncryptionForCMAC {
			encIcv := make([]byte, len(session.icv))

			err = desECBEncrypt(encIcv, session.icv[:], session.keys.cmacCipher)
			if err != nil {
				return apdu.Capdu{}, errors.Wrap(err, "failed to encrypt ICV with DES ECB")
			}

			// copy the value of the encrypted iv to the session icv
			copy(session.icv[:], encIcv)
		}

		// any indication of logical channel number shall be removed from the class byte
		if wrapped.Cla&byte(0x4F) != 0x00 {
			wrapped.Cla -= 0x4F
		}

		// remove le for CMAC calculation
		wrapped.Ne = 0

		bCapdu := wrapped.Bytes()

		// restore le
		wrapped.Ne = capdu.Ne

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
			return apdu.Capdu{}, errors.Wrap(err, "failed to pad data for CMAC calculation")
		}

		err = desFinalTDESMac(&cmac, bCapdu, session.keys.cmac, session.icv)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "failed to calculate CMAC with Single DES Final 3DES MAC")
		}

		// C-MAC on unmodified APDU
		if session.options.CMACOnUnmodifiedAPDU {
			if (wrapped.Cla & byte(0x04)) != 0x04 {
				wrapped.Cla += 0x04
			}
		}

		// calculated C-MAC is used as new ICV
		copy(session.icv[:], cmac[:])
	}

	// command encryption
	if level.CDEC && wrapped.Data != nil {
		dataCopy := wrapped.Data
		// pad
		dataCopy, err = Pad80(dataCopy, 8, true)
		if err != nil {
			return apdu.Capdu{}, errors.Wrap(err, "failed to pad data for encryption")
		}

		// use zero iv for encryption
		tdesCbcDec := cipher.NewCBCEncrypter(session.keys.encTDESCipher, scp02ZeroIV[:])
		result := make([]byte, len(dataCopy))
		tdesCbcDec.CryptBlocks(result, dataCopy)
		wrapped.Data = result
	}

	// append C-MAC after encryption
	if level.CMAC {
		wrapped.Data = append(wrapped.Data, cmac[:]...)
	}

	// set secure messaging bit
	if level.CMAC || level.CDEC {
		if (wrapped.Cla & byte(0x04)) != 0x04 {
			wrapped.Cla += 0x04
		}
	}

	return wrapped, nil
}

// Unwrap takes an apdu.Rapdu and verifies the R-MAC if an R-MAC session was started with Session and returns the unwrapped apdu.Rapdu.
func (session *Session) Unwrap(rapdu apdu.Rapdu) (apdu.Rapdu, error) {
	if session.rmacSession != nil {
		return session.rmacSession.unwrapWithSecurityLevel(rapdu)
	}

	return rapdu, nil
}

// EncryptDataWithDEK uses Triple DES in ECB mode for encrypting the given data with the session DEK.
// The length of src and dst must be a multiple of 8. If padding is required, it must be applied before calling the function.
func (session *Session) EncryptDataWithDEK(dst []byte, src []byte) error {
	err := tripleDESEcbEncrypt(dst, src, session.keys.dekTDES)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt data with TripleDES ECB")
	}

	return nil
}

// MaximumCommandPayloadLength returns the maximum length of payload for the data field of CAPDUs that are
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

func initializeUpdate(keyVersionNumber byte, hostChallenge [8]byte) apdu.Capdu {
	return apdu.Capdu{
		Cla:  claGP,
		Ins:  0x50,
		P1:   keyVersionNumber,
		P2:   0x00,
		Data: hostChallenge[:],
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

type keyInformation struct {
	Version byte
	SCPID   byte
}

func parseSCP02InitializeUpdateResponse(b []byte) (*initializeUpdateResponse, error) {
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

	keyInfo := keyInformation{Version: b[10], SCPID: b[11]}

	if keyInfo.SCPID != 0x02 {
		return nil, fmt.Errorf("scp ID must be 02, got %d", keyInfo.SCPID)
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
	KeyDiversificationData [10]byte       // key diversification data is data typically used by a backend system to derive the card static keys.
	KeyInformation         keyInformation // key information includes the Version Number and the Secure Channel Protocol identifier
	SequenceCounter        [2]byte        // current value of the sequence counter used for session key derivation
	CardChallenge          [6]byte        // random number generated by the card
	CardCryptogram         [8]byte        // authentication cryptogram generated by the card
}

func (session *Session) externalAuthenticate(hostCryptogram [8]byte) (apdu.Capdu, error) {
	ea := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x82,
		P1:   session.securityLevel.Byte(),
		P2:   0x00,
		Data: hostCryptogram[:],
		Ne:   0,
	}

	cmd, err := session.wrapWithSecurityLevel(ea, SecurityLevel{CMAC: true}, true)
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "failed to wrap EXTERNAL AUTHENTICATE command")
	}

	return cmd, nil
}

func (session *Session) calculateCardCryptogram(hc [8]byte, seqCounter [2]byte, cc [6]byte) ([8]byte, error) {
	ccInput := make([]byte, 0, 16)
	ccInput = append(ccInput, hc[:]...)
	ccInput = append(ccInput, seqCounter[:]...)
	ccInput = append(ccInput, cc[:]...)

	data, err := Pad80(ccInput, 24, false)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "failed to pad data for 3DES MAC")
	}

	var cryptogram [8]byte

	err = fullTDESMac(&cryptogram, data, session.keys.encTDESCipher, scp02ZeroIV)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "failed to calculate 3DES MAC")
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
		return [8]byte{}, errors.Wrap(err, "failed to pad data for 3DES MAC")
	}

	var cryptogram [8]byte

	err = fullTDESMac(&cryptogram, data, session.keys.encTDESCipher, scp02ZeroIV)
	if err != nil {
		return [8]byte{}, errors.Wrap(err, "failed to calculate 3DES MAC")
	}

	return cryptogram, nil
}

type sessionKeys struct {
	cmac          [16]byte
	rmac          [16]byte
	dekTDES       [24]byte
	cmacCipher    cipher.Block
	encTDESCipher cipher.Block
}

func deriveSessionKey(dst *[16]byte, keyProvider TripleDESCBCEncrypter, derivationConstant [2]byte, sequenceCounter [2]byte) error {
	var derivationData [16]byte

	copy(derivationData[:], append(derivationConstant[:], sequenceCounter[:]...))

	err := keyProvider.Encrypt(dst, derivationData)
	if err != nil {
		return errors.Wrap(err, "failed to apply TripleDES CBC encryption")
	}

	return nil
}

func (session *Session) deriveCMAC(provider TripleDESCBCEncrypter) error {
	var (
		derivedKey [16]byte
	)

	err := deriveSessionKey(&derivedKey, provider, [2]byte{0x01, 0x01}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "failed to derive S-CMAC")
	}

	copy(session.keys.cmac[:], derivedKey[:])

	session.keys.cmacCipher, err = des.NewCipher(derivedKey[:8])
	if err != nil {
		return errors.Wrap(err, "failed to create DES cipher from S-CMAC")
	}

	return nil
}

func (session *Session) deriveRMAC(provider TripleDESCBCEncrypter) error {
	var derivedKey [16]byte

	err := deriveSessionKey(&derivedKey, provider, [2]byte{0x01, 0x02}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "failed to derive RMAC")
	}

	copy(session.keys.rmac[:], derivedKey[:])

	return nil
}

func (session *Session) deriveDEK(provider TripleDESCBCEncrypter) error {
	var (
		derivedKey [16]byte
		tdesKey    [24]byte
	)

	err := deriveSessionKey(&derivedKey, provider, [2]byte{0x01, 0x81}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "failed to derive S-DEK")
	}

	tdesKey = resizeDoubleDESToTDES(derivedKey)

	copy(session.keys.dekTDES[:], tdesKey[:])

	return nil
}

func (session *Session) deriveENC(provider TripleDESCBCEncrypter) error {
	var (
		derivedKey [16]byte
		tdesKey    [24]byte
	)

	err := deriveSessionKey(&derivedKey, provider, [2]byte{0x01, 0x82}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "failed to derive S-ENC")
	}

	tdesKey = resizeDoubleDESToTDES(derivedKey)

	session.keys.encTDESCipher, err = des.NewTripleDESCipher(tdesKey[:])
	if err != nil {
		return errors.Wrap(err, "failed to create TripleDES cipher from S-ENC")
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

	session.sequenceCounter[0] += 0x01
}

// BeginRMACSession starts a R-MAC session. Data is used to specify the data field of the BEGIN R-MAC SESSION command.
// This function calls TripleDESCBCEncrypter.Encrypt on the encrypter for the MAC key, that was provided when creating Session, in order to derive the R-MAC key
// and calls APDUTransmitter.Transmit to transmit the BEGIN R-MAC SESSION CAPDU and receive the RAPDU.
func (session *Session) BeginRMACSession(transmitter APDUTransmitter, data []byte) error {
	skipUnlock := false

	session.lock.Lock()
	defer func() {
		if !skipUnlock {
			session.lock.Unlock()
		}
	}()

	rmac := [16]byte{}

	err := deriveSessionKey(&rmac, session.macEncrypter, [2]byte{0x01, 0x02}, session.sequenceCounter)
	if err != nil {
		return errors.Wrap(err, "failed to derive RMAC")
	}

	session.keys.rmac = rmac

	rmacSession := &RMACSession{}
	tKey := resizeDoubleDESToTDES(rmac)

	rmacSession.rmacTDESCipher, err = des.NewTripleDESCipher(tKey[:])
	if err != nil {
		return errors.Wrap(err, "failed to create TripleDESCipher from RMAC")
	}

	capdu, err := beginRMACSession(BeginRMACSessionP1RMAC, data)
	if err != nil {
		return errors.Wrap(err, "failed to create BEGIN R-MAC SESSION command")
	}

	session.lock.Unlock()
	skipUnlock = true

	wrapped, err := session.Wrap(capdu)
	if err != nil {
		return errors.Wrap(err, "failed to wrap BEGIN R-MAC SESSION command")
	}

	session.lock.Lock()
	skipUnlock = false

	wrapped.Cla = onLogicalChannel(session.channelID, wrapped.Cla)

	resp, err := transmitter.Transmit(wrapped)
	if err != nil {
		return errors.Wrap(err, "failed to transmit BEGIN R-MAC Session")
	}

	if !resp.IsSuccess() {
		return errors.Errorf("BEGIN R-MAC Session failed with SW: %02X%02X", resp.SW1, resp.SW2)
	}

	if session.selectedAid == nil {
		copy(rmacSession.ricv[:], session.externalAuthenticateCmac)
	} else {
		// pad data
		padded, err := Pad80(session.selectedAid, 8, true)
		if err != nil {
			return errors.Wrap(err, "failed to pad data for CMAC calculation")
		}

		// calculate the CMAC
		err = desFinalTDESMac(&rmacSession.ricv, padded, session.keys.rmac, scp02ZeroIV)
		if err != nil {
			return errors.Wrap(err, "failed to calculate CMAC with Single DES Final 3DES MAC")
		}
	}

	session.rmacSession = rmacSession

	return nil
}

// EndRMACSession ends an R-MAC session and/or retrieves the current R-MAC value depending on the value of endSession.
// This function calls APDUTransmitter.Transmit to transmit the END R-MAC SESSION CAPDU and receive the RAPDU.
func (session *Session) EndRMACSession(transmitter APDUTransmitter, endSession bool) (rmac []byte, err error) {
	skipUnlock := false

	session.lock.Lock()
	defer func() {
		if !skipUnlock {
			session.lock.Unlock()
		}
	}()

	if session.rmacSession == nil {
		return nil, errors.New("session has no active R-MAC session")
	}

	var p2 byte

	if endSession {
		p2 = EndRMACSessionP2EndAndReturnRMAC
	} else {
		p2 = EndRMACSessionP2ReturnRMAC
	}

	capdu := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x78,
		P1:   0x00,
		P2:   p2,
		Data: nil,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	session.lock.Unlock()
	skipUnlock = true

	wrapped, err := session.Wrap(capdu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to wrap END R-MAC SESSION command")
	}

	session.lock.Lock()
	skipUnlock = false

	wrapped.Cla = onLogicalChannel(session.channelID, wrapped.Cla)

	resp, err := transmitter.Transmit(wrapped)
	if err != nil {
		return nil, errors.Wrap(err, "failed to transmit END R-MAC Session")
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
		return apdu.Capdu{}, errors.New("invalid length of data for BEGIN R-MAC Session " +
			"- must be in range 1-25 bytes with first byte indicating the data length")
	}

	if p1 != BeginRMACSessionP1RMAC && p1 != BeginRMACSessionP1NoSecureMessaging {
		return apdu.Capdu{}, errors.New("invalid value for p1")
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
	channelID      byte
	lastCommand    []byte
	ricv           [8]byte
	rmac           [16]byte
	rmacTDESCipher cipher.Block
	lock           sync.Mutex
}

// End ends an R-MAC session and/or retrieves the current R-MAC value depending on the value of endSession.
// This function calls APDUTransmitter.Transmit to transmit the END R-MAC SESSION CAPDU and receive the RAPDU.
func (rmacSession *RMACSession) End(transmitter APDUTransmitter, endSession bool) ([]byte, error) {
	rmacSession.lock.Lock()
	defer rmacSession.lock.Unlock()

	var p2 byte

	if endSession {
		p2 = EndRMACSessionP2EndAndReturnRMAC
	} else {
		p2 = EndRMACSessionP2ReturnRMAC
	}

	capdu := apdu.Capdu{
		Cla:  claGP,
		Ins:  0x78,
		P1:   0x00,
		P2:   p2,
		Data: nil,
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	resp, err := transmitter.Transmit(capdu)
	if err != nil {
		return nil, errors.Wrap(err, "failed to transmit END R-MAC Session")
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
		return apdu.Rapdu{}, errors.New("no last command for RMAC calculation found - did you forget to call UpdateLastCommand?")
	}

	// get response data without R-MAC
	responseData := rapdu.Data[:len(rapdu.Data)-8]

	lenRmacInput := len(rmacSession.lastCommand) + len(responseData) + 3

	rmacInput := make([]byte, 0, lenRmacInput)
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
		return apdu.Rapdu{}, errors.Wrap(err, "failed to pad data for RMAC calculation")
	}

	var calculatedRmac [8]byte

	err = desFinalTDESMac(&calculatedRmac, rmacInput, rmacSession.rmac, rmacSession.ricv)
	if err != nil {
		return apdu.Rapdu{}, errors.Wrap(err, "failed to calculate RMAC with Single DES with Final 3DES Mac")
	}

	receivedRmac := rapdu.Data[len(rapdu.Data)-8:]

	if !bytes.Equal(calculatedRmac[:], receivedRmac) {
		return apdu.Rapdu{}, fmt.Errorf("calculated RMAC on host (%02X) doesn't match the calculated RMAC of the card (%02X)", calculatedRmac[:], receivedRmac)
	}

	// RMAC is used as ICV for next calculation
	copy(rmacSession.ricv[:], calculatedRmac[:])

	rapdu.Data = responseData

	return rapdu, nil
}