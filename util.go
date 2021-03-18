package scp02

func onLogicalChannel(channelID, cla byte) byte {
	if channelID <= 3 {
		return cla | channelID
	}

	if cla&0x40 != 0x40 {
		cla += 0x40
	}

	if channelID > 19 {
		channelID = 19
	}

	channelID -= 4

	return cla | (channelID & 0x0F)
}

func channelIDFromCLA(cla byte) byte {
	var channelID byte

	if cla&0x40 != 0x40 {
		channelID = cla & 0x03
	} else {
		channelID = 0x04
		channelID += cla & 0x0F
	}

	return channelID
}
