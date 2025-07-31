-- GSMTAP v3 Dissector for Wireshark - Improved Version
-- Based on the official GSMTAPv3 specification from Osmocom
-- convert to LUA scrip by https://www.youtube.com/c/RifkyTheCyber
-- support my channel in YT rifkythecyber by donate here: https://ko-fi.com/rifkythecyber
-- Place this file in your Wireshark plugins directory as gsmtapv3.lua

-- Protocol definition
local gsmtapv3_proto = Proto("gsmtapv3", "GSM Tap Version 3")

-- Header fields
local fields = gsmtapv3_proto.fields
fields.version     = ProtoField.uint8("gsmtapv3.version", "Version", base.DEC)
fields.res         = ProtoField.uint8("gsmtapv3.res", "Reserved", base.HEX)
fields.hdr_len     = ProtoField.uint16("gsmtapv3.hdr_len", "Header Length", base.DEC, nil, nil, "Length in 32-bit words")
fields.type        = ProtoField.uint16("gsmtapv3.type", "Type", base.HEX)
fields.sub_type    = ProtoField.uint16("gsmtapv3.sub_type", "Sub Type", base.HEX)
fields.metadata    = ProtoField.bytes("gsmtapv3.metadata", "Metadata")
fields.payload     = ProtoField.bytes("gsmtapv3.payload", "Payload")

-- TLV metadata fields
fields.tlv_type    = ProtoField.uint16("gsmtapv3.tlv.type", "TLV Type", base.HEX)
fields.tlv_length  = ProtoField.uint16("gsmtapv3.tlv.length", "TLV Length", base.DEC)
fields.tlv_value   = ProtoField.bytes("gsmtapv3.tlv.value", "TLV Value")

-- Type values from the actual GSMTAPv3 header
local type_names = {
    -- 0x00, 0x01: Common and non-3GPP protocols
    [0x0000] = "libosmocore Log",
    [0x0001] = "SIM Interface",
    [0x0002] = "Baseband Diagnostic",
    [0x0003] = "Signal Status Report",
    [0x0004] = "TETRA Air Interface",
    [0x0005] = "TETRA Air Interface Burst",
    [0x0006] = "GMR-1 UM",
    [0x0007] = "E1/T1 Lines",
    [0x0008] = "WiMAX Burst",
    
    -- 0x02: GSM
    [0x0200] = "GSM UM",
    [0x0201] = "GSM UM Burst",
    [0x0202] = "GPRS Gb RLC/MAC",
    [0x0203] = "GPRS Gb LLC",
    [0x0204] = "GPRS Gb SNDCP",
    [0x0205] = "GSM Abis",
    [0x0206] = "GSM RLP",
    
    -- 0x03: UMTS/WCDMA
    [0x0300] = "UMTS MAC",
    [0x0301] = "UMTS RLC",
    [0x0302] = "UMTS PDCP",
    [0x0303] = "UMTS RRC",
    
    -- 0x04: LTE
    [0x0400] = "LTE MAC",
    [0x0401] = "LTE RLC",
    [0x0402] = "LTE PDCP",
    [0x0403] = "LTE RRC",
    [0x0404] = "EPS NAS",
    
    -- 0x05: NR (5G)
    [0x0500] = "NR MAC",
    [0x0501] = "NR RLC",
    [0x0502] = "NR PDCP",
    [0x0503] = "NR RRC",
    [0x0504] = "5GS NAS"
}

-- Sub-type names for common types
local subtype_names = {
    -- SIM Interface (0x0001)
    [0x0001] = {
        [0x0001] = "APDU",
        [0x0002] = "ATR",
        [0x0003] = "PPS Request",
        [0x0004] = "PPS Response",
        [0x0005] = "TPDU Header",
        [0x0006] = "TPDU Command",
        [0x0007] = "TPDU Response",
        [0x0008] = "TPDU SW"
    },
    
    -- GSM UM (0x0200)
    [0x0200] = {
        [0x0000] = "Unknown Channel",
        [0x0001] = "BCCH",
        [0x0002] = "CCCH",
        [0x0003] = "RACH",
        [0x0004] = "AGCH",
        [0x0005] = "PCH",
        [0x0006] = "SDCCH",
        [0x0007] = "SDCCH/4",
        [0x0008] = "SDCCH/8",
        [0x0009] = "FACCH/F",
        [0x000a] = "FACCH/H",
        [0x000b] = "PACCH",
        [0x000c] = "CBCH52",
        [0x000d] = "PDCH",
        [0x000e] = "PTCCH",
        [0x000f] = "CBCH51",
        [0x0010] = "Voice/F",
        [0x0011] = "Voice/H",
        [0x0100] = "ACCH"
    },
    
    -- GSM UM Burst (0x0201)
    [0x0201] = {
        [0x0001] = "FCCH",
        [0x0002] = "Partial SCH",
        [0x0003] = "SCH",
        [0x0004] = "CTS SCH",
        [0x0005] = "Compact SCH",
        [0x0006] = "Normal",
        [0x0007] = "Dummy",
        [0x0008] = "Access",
        [0x0009] = "None"
    },
    
    -- LTE RRC (0x0403)
    [0x0403] = {
        [0x0001] = "BCCH-BCH",
        [0x0002] = "BCCH-BCH-MBMS",
        [0x0003] = "BCCH-DL-SCH",
        [0x0004] = "BCCH-DL-SCH-BR",
        [0x0005] = "BCCH-DL-SCH-MBMS",
        [0x0006] = "MCCH",
        [0x0007] = "PCCH",
        [0x0008] = "DL-CCCH",
        [0x0009] = "DL-DCCH",
        [0x000a] = "UL-CCCH",
        [0x000b] = "UL-DCCH",
        [0x000c] = "SC-MCCH"
    },
    
    -- NR RRC (0x0503)
    [0x0503] = {
        [0x0001] = "BCCH-BCH",
        [0x0002] = "BCCH-DL-SCH",
        [0x0003] = "DL-CCCH",
        [0x0004] = "DL-DCCH",
        [0x0005] = "MCCH",
        [0x0006] = "PCCH",
        [0x0007] = "UL-CCCH",
        [0x0008] = "UL-CCCH1",
        [0x0009] = "UL-DCCH"
    },
    
    -- NAS (0x0404, 0x0504)
    [0x0404] = {
        [0x0000] = "Plain",
        [0x0001] = "Security Header"
    },
    [0x0504] = {
        [0x0000] = "Plain",
        [0x0001] = "Security Header"
    }
}

-- Metadata TLV type values from the header
local tlv_type_names = {
    [0x0000] = "Packet Timestamp",
    [0x0001] = "Packet Comment",
    [0x0002] = "Channel Number",
    [0x0003] = "Frequency",
    [0x0004] = "Band Indicator",
    [0x0005] = "BSIC/PSC/PCI",
    [0x0006] = "GSM Timeslot",
    [0x0007] = "GSM Subslot",
    [0x0008] = "System Frame Number",
    [0x0009] = "Subframe Number",
    [0x000a] = "Hyperframe Number",
    [0x000b] = "TETRA Symbol Number",
    [0x000c] = "TETRA Multiframe Number",
    [0x000d] = "Antenna Number",
    
    [0x0100] = "Signal Level",
    [0x0101] = "RSSI",
    [0x0102] = "SNR", 
    [0x0103] = "SINR",
    [0x0104] = "RSCP",
    [0x0105] = "Ec/Io",
    [0x0106] = "RSRP",
    [0x0107] = "RSRQ",
    [0x0108] = "SS-RSRP",
    [0x0109] = "CSI-RSRP",
    [0x010a] = "SRS-RSRP",
    [0x010b] = "SS-RSRQ",
    [0x010c] = "CSI-RSRQ",
    [0x010d] = "SS-SINR",
    [0x010e] = "CSI-SINR",
    
    [0x0200] = "Ciphering Key",
    [0x0201] = "Integrity Key",
    [0x0202] = "K_NASenc",
    [0x0203] = "K_NASint",
    [0x0204] = "K_RRCenc",
    [0x0205] = "K_RRCint",
    [0x0206] = "K_UPenc",
    [0x0207] = "K_UPint"
}

-- Function to parse TLV metadata  
local function parse_metadata(buffer, pinfo, tree, offset, metadata_len)
    if metadata_len == 0 then
        return
    end
    
    local metadata_tree = tree:add(fields.metadata, buffer(offset, metadata_len))
    local current_offset = offset
    local end_offset = offset + metadata_len
    
    while current_offset < end_offset - 4 do  -- Need at least 4 bytes for T and L
        local tlv_type = buffer(current_offset, 2):uint()
        local tlv_length = buffer(current_offset + 2, 2):uint()
        
        if current_offset + 4 + tlv_length > end_offset then
            -- Malformed TLV, break
            metadata_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Malformed TLV - length extends beyond metadata")
            break
        end
        
        local tlv_tree = metadata_tree:add(buffer(current_offset, 4 + tlv_length), 
                                         string.format("TLV: %s (0x%04x)", 
                                         tlv_type_names[tlv_type] or "Unknown", tlv_type))
        
        tlv_tree:add(fields.tlv_type, buffer(current_offset, 2))
        tlv_tree:add(fields.tlv_length, buffer(current_offset + 2, 2))
        
        if tlv_length > 0 then
            tlv_tree:add(fields.tlv_value, buffer(current_offset + 4, tlv_length))
            
            -- Add specific parsing for known TLV types
            if tlv_type == 0x0000 and tlv_length >= 8 then  -- Packet Timestamp
                local timestamp = buffer(current_offset + 4, 8):uint64()
                tlv_tree:append_text(string.format(" = %d", timestamp:tonumber()))
            elseif tlv_type == 0x0001 then  -- Packet Comment (UTF-8 string)
                local comment = buffer(current_offset + 4, tlv_length):string()
                tlv_tree:append_text(string.format(" = \"%s\"", comment))
            elseif tlv_type == 0x0002 and tlv_length >= 2 then  -- Channel Number
                local channel = buffer(current_offset + 4, 2):uint()
                tlv_tree:append_text(string.format(" = %d", channel))
            elseif tlv_type == 0x0003 and tlv_length >= 4 then  -- Frequency
                local freq = buffer(current_offset + 4, 4):uint()
                tlv_tree:append_text(string.format(" = %d Hz", freq))
            elseif tlv_type == 0x0006 and tlv_length >= 1 then  -- GSM Timeslot
                local timeslot = buffer(current_offset + 4, 1):uint()
                tlv_tree:append_text(string.format(" = %d", timeslot))
            elseif tlv_type == 0x0008 and tlv_length >= 4 then  -- System Frame Number
                local sfn = buffer(current_offset + 4, 4):uint()
                tlv_tree:append_text(string.format(" = %d", sfn))
            elseif tlv_type == 0x0101 and tlv_length >= 2 then  -- RSSI
                local rssi = buffer(current_offset + 4, 2):int()
                tlv_tree:append_text(string.format(" = %d dBm", rssi))
            elseif tlv_type == 0x0106 and tlv_length >= 2 then  -- RSRP
                local rsrp = buffer(current_offset + 4, 2):int()
                tlv_tree:append_text(string.format(" = %d dBm", rsrp))
            elseif tlv_type == 0x0107 and tlv_length >= 2 then  -- RSRQ
                local rsrq = buffer(current_offset + 4, 2):int()
                tlv_tree:append_text(string.format(" = %d dB", rsrq))
            end
        end
        
        current_offset = current_offset + 4 + tlv_length
        
        -- Align to next 32-bit boundary if needed (based on spec)
        local remainder = (current_offset - offset) % 4
        if remainder ~= 0 then
            current_offset = current_offset + (4 - remainder)
        end
    end
end

-- Enhanced function to set up pinfo for NR-RRC dissection
local function setup_nr_rrc_pinfo(pinfo, sub_type)
    -- Set up the packet info for NR-RRC dissection
    -- This helps the NR-RRC dissector understand the channel type
    
    local channel_mapping = {
        [0x0001] = "bcch.bch",     -- BCCH-BCH
        [0x0002] = "bcch.dl.sch",  -- BCCH-DL-SCH
        [0x0003] = "dl.ccch",      -- DL-CCCH
        [0x0004] = "dl.dcch",      -- DL-DCCH
        [0x0005] = "mcch",         -- MCCH
        [0x0006] = "pcch",         -- PCCH
        [0x0007] = "ul.ccch",      -- UL-CCCH
        [0x0008] = "ul.ccch1",     -- UL-CCCH1
        [0x0009] = "ul.dcch"       -- UL-DCCH
    }
    
    local channel = channel_mapping[sub_type]
    if channel then
        pinfo.private["nr-rrc.channel_type"] = channel
    end
end

-- Enhanced function to set up pinfo for LTE-RRC dissection
local function setup_lte_rrc_pinfo(pinfo, sub_type)
    -- Set up the packet info for LTE-RRC dissection
    local channel_mapping = {
        [0x0001] = "bcch.bch",     -- BCCH-BCH
        [0x0002] = "bcch.bch.mbms", -- BCCH-BCH-MBMS
        [0x0003] = "bcch.dl.sch",  -- BCCH-DL-SCH
        [0x0004] = "bcch.dl.sch.br", -- BCCH-DL-SCH-BR
        [0x0005] = "bcch.dl.sch.mbms", -- BCCH-DL-SCH-MBMS
        [0x0006] = "mcch",         -- MCCH
        [0x0007] = "pcch",         -- PCCH
        [0x0008] = "dl.ccch",      -- DL-CCCH
        [0x0009] = "dl.dcch",      -- DL-DCCH
        [0x000a] = "ul.ccch",      -- UL-CCCH
        [0x000b] = "ul.dcch",      -- UL-DCCH
        [0x000c] = "sc.mcch"       -- SC-MCCH
    }
    
    local channel = channel_mapping[sub_type]
    if channel then
        pinfo.private["lte-rrc.channel_type"] = channel
    end
end

-- Enhanced function to get the appropriate dissector and channel info
local function get_dissector_info(msg_type, sub_type)
    local dissector_table = {
        -- GSM
        [0x0200] = {name = "gsm_um", setup = nil},
        [0x0201] = {name = "gsm_burst", setup = nil},
        
        -- UMTS
        [0x0303] = {name = "rrc", setup = nil},
        
        -- LTE
        [0x0400] = {name = "mac-lte", setup = nil},
        [0x0401] = {name = "rlc-lte", setup = nil},
        [0x0402] = {name = "pdcp-lte", setup = nil},
        [0x0403] = {name = "lte-rrc", setup = setup_lte_rrc_pinfo},
        [0x0404] = {name = "nas-eps", setup = nil},
        
        -- NR (5G)
        [0x0500] = {name = "mac-nr", setup = nil},
        [0x0501] = {name = "rlc-nr", setup = nil},
        [0x0502] = {name = "pdcp-nr", setup = nil},
        [0x0503] = {name = "nr-rrc", setup = setup_nr_rrc_pinfo},
        [0x0504] = {name = "nas-5gs", setup = nil},
        
        -- SIM
        [0x0001] = {name = "iso7816", setup = nil}
    }
    
    return dissector_table[msg_type]
end

-- Enhanced TETRA payload parsing function
-- Enhanced TETRA MCC/MNC parsing
local function parse_tetra_system_info(buffer, tree, offset)
    if buffer:len() < offset + 4 then
        return
    end
    
    local sys_info = buffer(offset, 3):uint()
    local sys_tree = tree:add(buffer(offset, 3), string.format("System Info: 0x%06x", sys_info))
    
    -- Parse TETRA system information according to ETSI EN 300 392-2
    -- Byte 0: 0x18 (PDU type info)
    -- Bytes 1-2: 0x5100 contains MCC/MNC info
    
    local byte0 = (sys_info >> 16) & 0xFF  -- 0x18
    local byte1 = (sys_info >> 8) & 0xFF   -- 0x51
    local byte2 = sys_info & 0xFF          -- 0x00
    
    -- Enhanced MCC extraction for TETRA
    -- In TETRA, MCC is often encoded differently than GSM
    local mcc_digit1 = (byte1 >> 4) & 0x0F  -- 5
    local mcc_digit2 = byte1 & 0x0F         -- 1
    local mcc_digit3 = (byte2 >> 4) & 0x0F  -- 0
    
    local mcc = mcc_digit1 * 100 + mcc_digit2 * 10 + mcc_digit3  -- 510
    
    -- MNC extraction - might be in different location
    local mnc = byte2 & 0x0F  -- Lower nibble
    
    -- Color code extraction (TETRA specific)
    local color_code = (byte0 >> 2) & 0x3F  -- Extract 6 bits for color code
    
    sys_tree:add(buffer(offset, 1), string.format("System Code: 0x%02x", byte0))
    sys_tree:add(buffer(offset + 1, 1), string.format("MCC: %d (digits: %d-%d-%d)", mcc, mcc_digit1, mcc_digit2, mcc_digit3))
    sys_tree:add(buffer(offset + 2, 1), string.format("MNC: %d", mnc))
    sys_tree:add(buffer(offset, 1), string.format("Color Code: %d", color_code))
    
    return mcc, mnc, color_code
end

-- Enhanced TETRA timing information parser
local function parse_tetra_timing(buffer, tree, offset)
    if buffer:len() < offset + 4 then
        return
    end
    
    local timing = buffer(offset, 4):uint()
    local timing_tree = tree:add(buffer(offset, 4), string.format("Timing Info: 0x%08x", timing))
    
    -- TETRA timing structure (based on ETSI EN 300 392-2)
    -- Bits 31-18: Frame Number (14 bits) - max 16383
    -- Bits 17-15: Slot Number (3 bits) - 0-7
    -- Bits 14-8:  Multiframe Number (7 bits) - 0-127
    -- Bits 7-0:   Additional timing info
    
    local frame_number = (timing >> 18) & 0x3FFF     -- 14 bits
    local slot_number = (timing >> 15) & 0x07        -- 3 bits
    local multiframe = (timing >> 8) & 0x7F          -- 7 bits
    local subslot = timing & 0xFF                     -- 8 bits
    
    timing_tree:add(buffer(offset, 2), string.format("Frame Number: %d (14-bit)", frame_number))
    timing_tree:add(buffer(offset + 2, 1), string.format("Slot Number: %d (0-7)", slot_number))
    timing_tree:add(buffer(offset + 2, 1), string.format("Multiframe: %d (0-127)", multiframe))
    timing_tree:add(buffer(offset + 3, 1), string.format("Subslot/Timing: %d", subslot))
    
    -- Calculate absolute timing
    local absolute_time = frame_number * 8 + slot_number
    timing_tree:add(buffer(offset, 4), string.format("Absolute Slot: %d", absolute_time))
    
    return frame_number, slot_number, multiframe
end

-- Enhanced TETRA MAC-BROADCAST PDU parser
local function parse_tetra_mac_broadcast(buffer, tree, offset, length)
    local mac_tree = tree:add(buffer(offset, length), "MAC-BROADCAST PDU Analysis")
    
    if length < 8 then
        mac_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "MAC-BROADCAST PDU too short")
        return
    end
    
    -- Parse PDU type and flags
    local pdu_byte = buffer(offset, 1):uint()
    local pdu_tree = mac_tree:add(buffer(offset, 1), string.format("PDU Header: 0x%02x", pdu_byte))
    
    -- Analyze PDU structure bits
    local tm_sdu_present = (pdu_byte & 0x80) ~= 0
    local basic_slot_grant = (pdu_byte & 0x40) ~= 0
    local advanced_link = (pdu_byte & 0x20) ~= 0
    
    pdu_tree:add(buffer(offset, 1), string.format("TM-SDU Present: %s", tm_sdu_present and "Yes" or "No"))
    pdu_tree:add(buffer(offset, 1), string.format("Basic Slot Grant: %s", basic_slot_grant and "Yes" or "No"))
    pdu_tree:add(buffer(offset, 1), string.format("Advanced Link: %s", advanced_link and "Yes" or "No"))
    
    -- Parse system information
    parse_tetra_system_info(buffer, mac_tree, offset + 1)
    
    -- Parse timing information
    if length >= 8 then
        parse_tetra_timing(buffer, mac_tree, offset + 4)
    end
    
    -- Parse additional fields if present
    if length > 8 then
        local additional_offset = offset + 8
        local additional_length = length - 8
        
        local additional_tree = mac_tree:add(buffer(additional_offset, additional_length), 
                                           string.format("Additional Data (%d bytes)", additional_length))
        
        -- Look for common TETRA information elements
        if additional_length >= 2 then
            local elem_type = buffer(additional_offset, 1):uint()
            local elem_length = buffer(additional_offset + 1, 1):uint()
            
            if elem_type == 0x12 then  -- System info type 1
                additional_tree:add(buffer(additional_offset, 2), "Information Element: System Info Type 1")
            elseif elem_type == 0x34 then  -- Access rights
                additional_tree:add(buffer(additional_offset, 2), "Information Element: Access Rights")
            elseif elem_type == 0x56 then  -- Service details
                additional_tree:add(buffer(additional_offset, 2), "Information Element: Service Details")
            else
                additional_tree:add(buffer(additional_offset, 2), string.format("Information Element: Type 0x%02x, Length %d", elem_type, elem_length))
            end
        end
        
        -- Add hex dump for remaining data
        local hex_data = ""
        for i = 0, math.min(additional_length - 1, 15) do
            hex_data = hex_data .. string.format("%02x ", buffer(additional_offset + i, 1):uint())
        end
        if additional_length > 16 then
            hex_data = hex_data .. "..."
        end
        additional_tree:append_text(string.format(" [%s]", hex_data:sub(1, -2)))
    end
end

-- Enhanced TETRA subtype descriptions
local tetra_subtypes = {
    [0x0000] = "Unknown/Generic",
    [0x0001] = "BCCH (Broadcast Control Channel)",
    [0x0002] = "TCH (Traffic Channel)", 
    [0x0003] = "STCH (Slow Traffic Channel)",
    [0x0004] = "SCH/HD (Sync Channel/Half Duplex)",
    [0x0005] = "Group Call",
    [0x0006] = "Emergency Call",
    [0x0007] = "Private Call",
    [0x0008] = "Data Transmission",
    [0x0009] = "Status Message",
    [0x000A] = "Short Data Service",
    [0x000B] = "Supplementary Service",
    [0x000C] = "OTAR (Over The Air Rekeying)",
    [0x000D] = "Air Interface Encryption",
    [0x000E] = "Network Management",
    [0x000F] = "Location Services"
}

-- Function to get TETRA subtype description
local function get_tetra_subtype_description(sub_type)
    return tetra_subtypes[sub_type] or string.format("Unknown (0x%04x)", sub_type)
end

-- Enhanced main TETRA payload parser (replacement for your existing function)
local function parse_tetra_payload_enhanced(buffer, pinfo, tree, offset, length, sub_type)
    print("GSMTAPV3: Enhanced TETRA payload parsing, length=" .. length .. ", subtype=0x" .. string.format("%04x", sub_type))
    
    if length < 2 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "TETRA payload too short")
        return
    end
    
    -- Create enhanced TETRA protocol tree
    local tetra_tree = tree:add(buffer(offset, length), "TETRA Protocol Analysis")
    local subtype_desc = get_tetra_subtype_description(sub_type)
    tetra_tree:append_text(string.format(" (%s)", subtype_desc))
    
    -- Set protocol column info
    pinfo.cols.protocol = "TETRA"
    if pinfo.cols.info == "" then
        pinfo.cols.info = string.format("TETRA %s", subtype_desc)
    end
    
    -- Parse based on sub-type with enhanced analysis
    if sub_type == 0x0001 then  -- BCCH
        parse_tetra_mac_broadcast(buffer, tetra_tree, offset, length)
        
    elseif sub_type == 0x0002 then  -- TCH
        tetra_tree:append_text(" - Traffic Channel")
        
        if length >= 4 then
            local tch_header = buffer(offset, 2):uint()
            local tch_tree = tetra_tree:add(buffer(offset, 2), string.format("TCH Header: 0x%04x", tch_header))
            
            local speech_flag = (tch_header & 0x8000) ~= 0
            local codec_type = (tch_header >> 8) & 0x7F
            local frame_type = tch_header & 0xFF
            
            tch_tree:add(buffer(offset, 1), string.format("Speech Flag: %s", speech_flag and "Voice" or "Data"))
            tch_tree:add(buffer(offset, 1), string.format("Codec Type: 0x%02x", codec_type))
            tch_tree:add(buffer(offset + 1, 1), string.format("Frame Type: 0x%02x", frame_type))
            
            -- REPLACE THE EXISTING codec_desc SECTION WITH THIS:
            local codec_desc = "Unknown"
            if codec_type == 0x2C then
                codec_desc = "ACELP (Algebraic Code Excited Linear Prediction)"
            elseif codec_type == 0x15 then
                codec_desc = "PCM (Pulse Code Modulation)"
            elseif codec_type == 0x08 then
                codec_desc = "TETRA Standard Voice Codec"
            -- Add these new codec types:
            elseif codec_type == 0x00 then
                codec_desc = "Data Channel (No Voice Codec)"
            elseif codec_type == 0x01 then
                codec_desc = "TETRA Enhanced Voice Codec"
            elseif codec_type == 0x02 then
                codec_desc = "TETRA Compressed Voice"
            elseif codec_type == 0x10 then
                codec_desc = "Digital Data Transmission"
            elseif codec_type == 0x20 then
                codec_desc = "Analog Bridge Codec"
            elseif codec_type == 0x30 then
                codec_desc = "High Quality Voice Codec"
            end
            tch_tree:add(buffer(offset, 1), "Codec Description: " .. codec_desc)
        end
        
     elseif sub_type == 0x0005 then  -- Group Call
        if length >= 6 then
            local group_info = buffer(offset, 4):uint()
            local group_tree = tetra_tree:add(buffer(offset, 4), string.format("Group Call Info: 0x%08x", group_info))
            
            local group_id = (group_info >> 16) & 0xFFFF
            local call_type = (group_info >> 8) & 0xFF
            local priority = group_info & 0xFF
            
            group_tree:add(buffer(offset, 2), string.format("Group ID: %d", group_id))
            group_tree:add(buffer(offset + 2, 1), string.format("Call Type: 0x%02x", call_type))
            group_tree:add(buffer(offset + 3, 1), string.format("Priority: %d", priority))
            
            -- REPLACE THE EXISTING call_desc SECTION WITH THIS:
            local call_desc = "Unknown"
            if call_type == 0x85 then
                call_desc = "Emergency Group Call"
            elseif call_type == 0x42 then
                call_desc = "Routine Group Call"
            elseif call_type == 0x63 then
                call_desc = "Priority Group Call"
            -- Add these new call types:
            elseif call_type == 0x12 then
                call_desc = "Tactical Group Call"
            elseif call_type == 0x21 then
                call_desc = "Operational Group Call"
            elseif call_type == 0x34 then
                call_desc = "Administrative Group Call"
            elseif call_type == 0x45 then
                call_desc = "Training Group Call"
            elseif call_type == 0x56 then
                call_desc = "Maintenance Group Call"
            elseif call_type == 0x67 then
                call_desc = "Test Group Call"
            elseif call_type == 0x78 then
                call_desc = "Broadcast Group Call"
             elseif call_type == 0x50 then
    			call_desc = "Standard Group Call"
			elseif call_type == 0x51 then
    			call_desc = "Acknowledged Group Call"
			elseif call_type == 0x52 then
    			call_desc = "Broadcast Group Call"
			elseif call_type == 0x53 then
   				 call_desc = "Emergency Broadcast Call"
			elseif call_type == 0x60 then
   				 call_desc = "Individual Call"
			elseif call_type == 0x61 then
  			  call_desc = "PSTN Gateway Call"
			elseif call_type == 0x70 then
  			  call_desc = "Status Message Call"
			elseif call_type == 0x80 then
  			  call_desc = "Short Data Service Call"
			elseif call_type == 0x90 then
 			   call_desc = "Packet Data Call"
			elseif call_type == 0xA0 then
    		    call_desc = "Location Request Call"
            end
            group_tree:add(buffer(offset + 2, 1), "Call Description: " .. call_desc)
        end
    else
        -- Generic TETRA data parsing
        tetra_tree:append_text(" - Generic TETRA Data")
        
        if length >= 2 then
            local header = buffer(offset, 2):uint()
            tetra_tree:add(buffer(offset, 2), string.format("TETRA Header: 0x%04x", header))
            
            -- Try to identify common patterns
            if (header & 0xFF00) == 0x1800 then
                tetra_tree:add(buffer(offset, 1), "Pattern: Broadcast Channel")
            elseif (header & 0xFF00) == 0x4200 then
                tetra_tree:add(buffer(offset, 1), "Pattern: Traffic Channel")
            elseif (header & 0xFF00) == 0x8500 then
                tetra_tree:add(buffer(offset, 1), "Pattern: Control Channel")
            end
        end
    end
    
    -- Add summary statistics
    tetra_tree:add(buffer(offset, length), string.format("Total Payload Length: %d bytes", length))
    
    print("GSMTAPV3: Enhanced TETRA payload parsing completed")
end

-- Main dissector function
-- Main dissector function
function gsmtapv3_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 8 then
        return 0  -- Not enough data for GSMTAP v3 header
    end
    
    -- ADD THIS SECTION HERE:
    local gsmtap_offset = 0
    -- Check if buffer starts with IP header (0x45) and skip IP+UDP headers
    if length > 28 and buffer(0, 1):uint() == 0x45 then
        gsmtap_offset = 28  -- Skip 20-byte IP header + 8-byte UDP header
        if length < gsmtap_offset + 8 then
            return 0  -- Not enough data after skipping headers
        end
    end
    
    -- Check if this looks like a GSMTAP v3 packet (at correct offset)
    local version = buffer(gsmtap_offset, 1):uint()
    if version ~= 3 then
        return 0  -- Not GSMTAP v3
    end
    
    pinfo.cols.protocol = gsmtapv3_proto.name
    
    -- Create the protocol tree (using correct offset)
    local gsmtap_buffer = buffer(gsmtap_offset):tvb()
    local gsmtap_length = gsmtap_buffer:len()
    local subtree = tree:add(gsmtapv3_proto, gsmtap_buffer(), "GSMTAP v3")
    
    -- Parse header fields
    subtree:add(fields.version, gsmtap_buffer(0, 1))
    local res = gsmtap_buffer(1, 1):uint()
    local res_tree = subtree:add(fields.res, gsmtap_buffer(1, 1))
    if res ~= 0 then
        res_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Reserved field is not zero")
    end
    
    local hdr_len_words = gsmtap_buffer(2, 2):uint()
    local hdr_len_bytes = hdr_len_words * 4
    subtree:add(fields.hdr_len, gsmtap_buffer(2, 2)):append_text(string.format(" (%d bytes)", hdr_len_bytes))
    
    -- Validate header length
    if hdr_len_words < 2 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Invalid header length (less than minimum)")
        return gsmtap_length
    end
    
    if hdr_len_bytes > gsmtap_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Header length exceeds packet size")
        return gsmtap_length
    end
    
    local msg_type = gsmtap_buffer(4, 2):uint()
    local type_tree = subtree:add(fields.type, gsmtap_buffer(4, 2))
    if type_names[msg_type] then
        type_tree:append_text(string.format(" (%s)", type_names[msg_type]))
    end
    
    local sub_type = gsmtap_buffer(6, 2):uint()
    local subtype_tree = subtree:add(fields.sub_type, gsmtap_buffer(6, 2))
    if subtype_names[msg_type] and subtype_names[msg_type][sub_type] then
        subtype_tree:append_text(string.format(" (%s)", subtype_names[msg_type][sub_type]))
    end
    
    -- Set column info
    if type_names[msg_type] then
        if subtype_names[msg_type] and subtype_names[msg_type][sub_type] then
            pinfo.cols.info = string.format("GSMTAP v3: %s (%s)", 
                                          type_names[msg_type], 
                                          subtype_names[msg_type][sub_type])
        else
            pinfo.cols.info = string.format("GSMTAP v3: %s (SubType: 0x%04x)", 
                                          type_names[msg_type], sub_type)
        end
    else
        pinfo.cols.info = string.format("GSMTAP v3: Type 0x%04x, SubType 0x%04x", msg_type, sub_type)
    end
    
    -- Parse metadata if present
    if hdr_len_bytes > 8 then
        local metadata_len = hdr_len_bytes - 8
        parse_metadata(gsmtap_buffer, pinfo, subtree, 8, metadata_len)
    end
    
    -- Add payload if present
    -- Add payload if present
    if gsmtap_length > hdr_len_bytes then
        local payload_len = gsmtap_length - hdr_len_bytes
        local payload_tree = subtree:add(fields.payload, gsmtap_buffer(hdr_len_bytes, payload_len))
        
        -- Try to dissect the payload based on type
        local payload_buffer = gsmtap_buffer(hdr_len_bytes, payload_len):tvb()
        
        -- Enhanced TETRA payload dissection
        if msg_type == 0x0004 or msg_type == 0x0005 then  -- TETRA Air Interface or Burst
            print("GSMTAPV3: Attempting TETRA payload dissection...")

--[[            
            -- Try TETRA dissector first
            local tetra_dissector = Dissector.get("tetra")
            if tetra_dissector then
                print("GSMTAPV3: Found TETRA dissector, calling it...")
                local result = tetra_dissector:call(payload_buffer, pinfo, tree)
                if result and result > 0 then
                    print("GSMTAPV3: TETRA dissector successfully processed payload")
                    payload_tree:append_text(" (Decoded by TETRA dissector)")
                    return gsmtap_length
                else
                    print("GSMTAPV3: TETRA dissector couldn't process payload")
                end
            else
                print("GSMTAPV3: TETRA dissector not found")
            end
--]]
            
            -- If TETRA dissector fails, use our custom TETRA parsing
            -- If TETRA dissector fails, use our custom TETRA parsing
			print("GSMTAPV3: Using custom TETRA parsing...")
			parse_tetra_payload_enhanced(gsmtap_buffer, pinfo, payload_tree, hdr_len_bytes, payload_len, sub_type) -- <-- Change this line
            payload_tree:append_text(" (Analyzed by GSMTAPv3)")
            
        else
            -- For non-TETRA types, try generic dissection
            print("GSMTAPV3: Non-TETRA payload, trying generic dissection...")
            
            -- Get dissector information for other types
            local dissector_info = get_dissector_info(msg_type, sub_type)
            if dissector_info then
                print("GSMTAPV3: Found dissector info for type 0x" .. string.format("%04x", msg_type))
                
                -- Setup pinfo for specific dissectors if needed
                if dissector_info.setup then
                    dissector_info.setup(pinfo, sub_type)
                end
                
                -- Try multiple dissector names/variations
                local dissector_variants = {dissector_info.name}
                
                -- Add specific channel variants for NR-RRC
                if msg_type == 0x0503 then  -- NR RRC
                    local nr_rrc_dissectors = {
                        [0x0001] = {"nr-rrc.bcch.bch"},
                        [0x0002] = {"nr-rrc.bcch.dl.sch"},
                        [0x0003] = {"nr-rrc.dl.ccch"},
                        [0x0004] = {"nr-rrc.dl.dcch"},
                        [0x0005] = {"nr-rrc.mcch"},
                        [0x0006] = {"nr-rrc.pcch"},
                        [0x0007] = {"nr-rrc.ul.ccch"},
                        [0x0008] = {"nr-rrc.ul.ccch1"},
                        [0x0009] = {"nr-rrc.ul.dcch"}
                    }
                    
                    if nr_rrc_dissectors[sub_type] then
                        for _, dissector_name in ipairs(nr_rrc_dissectors[sub_type]) do
                            table.insert(dissector_variants, dissector_name)
                        end
                    end
                end
                
                -- Add specific channel variants for LTE-RRC  
                if msg_type == 0x0403 then  -- LTE RRC
                    local channel_suffixes = {
                        [0x0001] = "bcch_bch",
                        [0x0003] = "bcch_dl_sch",
                        [0x0007] = "pcch",
                        [0x0008] = "dl_ccch",
                        [0x0009] = "dl_dcch",
                        [0x000a] = "ul_ccch",
                        [0x000b] = "ul_dcch"
                    }
                    
                    if channel_suffixes[sub_type] then
                        table.insert(dissector_variants, "lte-rrc." .. channel_suffixes[sub_type])
                    end
                end
                
                -- Try each dissector variant
                local dissector_found = false
                for _, dissector_name in ipairs(dissector_variants) do
                    local subdissector = Dissector.get(dissector_name)
                    if subdissector then
                        print("GSMTAPV3: Trying " .. dissector_name .. " dissector...")
                        local result = subdissector:call(payload_buffer, pinfo, tree)
                        if result and result > 0 then
                            print("GSMTAPV3: " .. dissector_name .. " dissector successful")
                            payload_tree:append_text(" (Decoded by " .. dissector_name .. ")")
                            dissector_found = true
                            break
                        end
                    end
                end
                
                if not dissector_found then
                    payload_tree:append_text(" (No suitable dissector found)")
                end
            else
                payload_tree:append_text(" (Unknown message type)")
            end
        end
        
        -- Add hex dump for debugging (for smaller payloads)
        if payload_len <= 32 then
            local hex_string = ""
            for i = 0, payload_len - 1 do
                hex_string = hex_string .. string.format("%02x ", gsmtap_buffer(hdr_len_bytes + i, 1):uint())
            end
            payload_tree:append_text(string.format(" [%s]", hex_string:sub(1, -2)))
        end
    end
    
    return gsmtap_length
end

-- Register the protocol on UDP port 4729 (GSMTAP standard port)
-- Register the protocol on UDP port 4729 (GSMTAP standard port)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(4729, gsmtapv3_proto)

-- Register for handling as a heuristic dissector with enhanced detection
gsmtapv3_proto:register_heuristic("udp", function(buffer, pinfo, tree)
    print("GSMTAPV3: Heuristic called, buffer length=" .. buffer:len())
    
    if buffer:len() < 8 then
        print("GSMTAPV3: Heuristic - buffer too small")
        return false
    end
    
    -- Check for version 3 at start of buffer
    local version1 = buffer(0, 1):uint()
    print("GSMTAPV3: Heuristic - version at offset 0 = " .. version1)
    if version1 == 3 then
        print("GSMTAPV3: Heuristic - found version 3 at offset 0, calling dissector")
        gsmtapv3_proto.dissector(buffer, pinfo, tree)
        return true
    end
    
    -- Check for version 3 after IP+UDP headers (offset 28)
    if buffer:len() > 28 then
        local version2 = buffer(28, 1):uint()
        print("GSMTAPV3: Heuristic - version at offset 28 = " .. version2)
        if version2 == 3 then
            print("GSMTAPV3: Heuristic - found version 3 at offset 28, calling dissector")
            gsmtapv3_proto.dissector(buffer, pinfo, tree)
            return true
        end
    end
    
    print("GSMTAPV3: Heuristic - no version 3 found, returning false")
    return false
end)

-- Allow manual decode-as selection
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add_for_decode_as(gsmtapv3_proto)

-- Debug message to confirm plugin loaded
print("GSMTAPV3: Plugin loaded and registered for UDP port 4729")