package scp02

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/pkg/errors"
)

// Pad80 takes Data and a block size (must be a multiple of 8) and appends '80' and zero bytes to Data until
// the length of the resulting []byte reaches a multiple of the block size and returns the padded Data.
// If force is false, the padding will only be applied, if length of Data is not a multiple of the block size.
// If force is true, the padding will be applied anyways.
func Pad80(b []byte, blocksize int, force bool) ([]byte, error) {
	if blocksize%8 != 0 {
		return nil, errors.New("block size must be a multiple of 8")
	}

	rest := len(b) % blocksize
	if rest != 0 || force {
		padded := make([]byte, len(b)+blocksize-rest)
		copy(padded, b)
		padded[len(b)] = 0x80

		return padded, nil
	}

	return b, nil
}

func resizeDoubleDESToTDES(key [16]byte) [24]byte {
	var k [24]byte

	copy(k[:], key[:])
	copy(k[16:], key[:9])

	return k
}

func desECBEncrypt(dst []byte, src []byte, desCipher cipher.Block) error {
	if len(dst)%desCipher.BlockSize() != 0 {
		return errors.New("dst length is not a multiple of the block size")
	}

	if len(src)%desCipher.BlockSize() != 0 {
		return errors.New("src length is not a multiple of the block v")
	}

	for len(src) > 0 {
		desCipher.Encrypt(dst, src)
		src = src[desCipher.BlockSize():]
		dst = dst[desCipher.BlockSize():]
	}

	return nil
}

func desECBDecrypt(dst []byte, src []byte, desCipher cipher.Block) error {
	if len(dst)%desCipher.BlockSize() != 0 {
		return errors.New("dst length is not a multiple of the block size")
	}

	if len(src) < desCipher.BlockSize() {
		return errors.New("src length is not a multiple of the block size")
	}

	for len(src) > 0 {
		desCipher.Decrypt(dst, src)
		src = src[desCipher.BlockSize():]
		dst = dst[desCipher.BlockSize():]
	}

	return nil
}

func desFinalTDESMac(dst *[8]byte, src []byte, key [16]byte, iv [8]byte) error {
	if len(src)%des.BlockSize != 0 {
		return errors.New("length of src must be a multiple of 8")
	}

	tdesKey := resizeDoubleDESToTDES(key)
	sdesKey := key[:8]

	// get key as single des
	sdes, err := des.NewCipher(sdesKey)
	if err != nil {
		return errors.Wrap(err, "failed to create DES cipher")
	}

	tdes, err := des.NewTripleDESCipher(tdesKey[:])
	if err != nil {
		return errors.Wrap(err, "failed to create TDES cipher")
	}

	tdesCbc := cipher.NewCBCEncrypter(tdes, iv[:])

	if len(src) > 8 {
		// first do simple DES
		sdesCbc := cipher.NewCBCEncrypter(sdes, iv[:])
		tmp1 := make([]byte, len(src)-des.BlockSize)
		sdesCbc.CryptBlocks(tmp1, src[:len(src)-des.BlockSize])
		// use the result as IV for TDES
		tdesCbc = cipher.NewCBCEncrypter(tdes, tmp1[len(tmp1)-des.BlockSize:])
	}

	tdesCbc.CryptBlocks(dst[:], src[len(src)-des.BlockSize:])

	return nil
}

func fullTDESMac(dst *[8]byte, src []byte, tdesCipher cipher.Block, iv [8]byte) error {
	if len(dst)%tdesCipher.BlockSize() != 0 {
		return errors.New("dst length is not a multiple of the block length")
	}

	if len(src)%tdesCipher.BlockSize() != 0 {
		return errors.New("src length is not a multiple of the block length")
	}

	tdesCbc := cipher.NewCBCEncrypter(tdesCipher, iv[:])

	result := make([]byte, len(src))
	tdesCbc.CryptBlocks(result, src)
	copy(dst[:], result[len(result)-8:])

	return nil
}

func tripleDESEcbEncrypt(dst []byte, src []byte, key [24]byte) error {
	if len(dst)%des.BlockSize != 0 {
		return errors.New("dst length is not a multiple of the block length")
	}

	if len(src)%des.BlockSize != 0 {
		return errors.New("src length is not a multiple of the block length")
	}

	k1 := key[:8]

	resultFirst := make([]byte, len(src))

	block, err := des.NewCipher(k1)
	if err != nil {
		return errors.New("failed to create DES cipher for first DES round")
	}

	err = desECBEncrypt(resultFirst, src, block)
	if err != nil {
		return errors.Wrap(err, "failed to apply first round of DES encryption")
	}

	k2 := key[8:16]

	block2, err := des.NewCipher(k2)
	if err != nil {
		return errors.New("failed to create DES cipher for second DES round")
	}

	resultSecond := make([]byte, len(src))

	err = desECBDecrypt(resultSecond, resultFirst, block2)
	if err != nil {
		return errors.Wrap(err, "failed to apply second round of DES encryption")
	}

	k3 := key[16:]

	block3, err := des.NewCipher(k3)
	if err != nil {
		return errors.New("failed to create DES cipher for third DES round")
	}

	err = desECBEncrypt(dst, resultSecond, block3)
	if err != nil {
		return errors.Wrap(err, "failed to apply third round of DES encryption")
	}

	return nil
}
