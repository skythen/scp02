package scp02

import (
	"reflect"
)

func isNil(v interface{}) bool {
	return v == nil || (reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil())
}

func onLogicalChannel(channelID, cla byte) byte {
	if channelID <= 3 {
		cla = cla | channelID

		return cla
	}

	if cla&0x40 != 0x40 {
		cla += 0x40
	}

	if channelID > 19 {
		channelID = 19
	}

	channelID -= 4

	cla = cla | (channelID & 0x0F)

	return cla
}

func getChannelID(cla byte) byte {
	var channelID byte

	if cla&0x40 != 0x40 {
		channelID = cla & 0x03
	} else {
		channelID = 0x04
		channelID += cla & 0x0F
	}

	return channelID
}
