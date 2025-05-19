-- GSMTAP v3 Dissector for Wireshark
-- Based on the official GSMTAPv3 specification from Osmocom
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

-- Main dissector function
function gsmtapv3_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 8 then
        return 0  -- Not enough data for GSMTAP v3 header
    end
    
    -- Check if this looks like a GSMTAP v3 packet
    local version = buffer(0, 1):uint()
    if version ~= 3 then
        return 0  -- Not GSMTAP v3
    end
    
    pinfo.cols.protocol = gsmtapv3_proto.name
    
    -- Create the protocol tree
    local subtree = tree:add(gsmtapv3_proto, buffer(), "GSMTAP v3")
    
    -- Parse header fields
    subtree:add(fields.version, buffer(0, 1))
    local res = buffer(1, 1):uint()
    local res_tree = subtree:add(fields.res, buffer(1, 1))
    if res ~= 0 then
        res_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Reserved field is not zero")
    end
    
    local hdr_len_words = buffer(2, 2):uint()
    local hdr_len_bytes = hdr_len_words * 4
    subtree:add(fields.hdr_len, buffer(2, 2)):append_text(string.format(" (%d bytes)", hdr_len_bytes))
    
    -- Validate header length
    if hdr_len_words < 2 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Invalid header length (less than minimum)")
        return length
    end
    
    if hdr_len_bytes > length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Header length exceeds packet size")
        return length
    end
    
    local msg_type = buffer(4, 2):uint()
    local type_tree = subtree:add(fields.type, buffer(4, 2))
    if type_names[msg_type] then
        type_tree:append_text(string.format(" (%s)", type_names[msg_type]))
    end
    
    local sub_type = buffer(6, 2):uint()
    local subtype_tree = subtree:add(fields.sub_type, buffer(6, 2))
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
        parse_metadata(buffer, pinfo, subtree, 8, metadata_len)
    end
    
    -- Add payload if present
    if length > hdr_len_bytes then
        local payload_len = length - hdr_len_bytes
        subtree:add(fields.payload, buffer(hdr_len_bytes, payload_len))
        
        -- Try to dissect the payload based on type
        local payload_buffer = buffer(hdr_len_bytes, payload_len):tvb()
        
        -- Call appropriate sub-dissector based on type
        local dissector_name = nil
        if msg_type == 0x0303 then      -- UMTS RRC
            dissector_name = "rrc"
        elseif msg_type == 0x0403 then  -- LTE RRC
            dissector_name = "lte-rrc"
        elseif msg_type == 0x0400 then  -- LTE MAC
            dissector_name = "mac-lte"
        elseif msg_type == 0x0404 then  -- EPS NAS
            dissector_name = "nas-eps"
        elseif msg_type == 0x0503 then  -- NR RRC
            dissector_name = "nr-rrc"
        elseif msg_type == 0x0504 then  -- 5GS NAS
            dissector_name = "nas-5gs"
        elseif msg_type == 0x0200 then  -- GSM UM
            dissector_name = "gsm_um"
        end
        
        if dissector_name then
            local subdissector = Dissector.get(dissector_name)
            if subdissector then
                subdissector:call(payload_buffer, pinfo, tree)
            end
        end
    end
    
    return length
end

-- Register the protocol on UDP port 4729 (GSMTAP standard port)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(4729, gsmtapv3_proto)

-- Register for handling as a heuristic dissector
gsmtapv3_proto:register_heuristic("udp", function(buffer, pinfo, tree)
    if buffer:len() < 8 then
        return false
    end
    
    local version = buffer(0, 1):uint()
    if version == 3 then
        gsmtapv3_proto.dissector(buffer, pinfo, tree)
        return true
    end
    
    return false
end)

-- Register as a dissector that can be manually selected
gsmtapv3_proto:register_heuristic("udp", function(buffer, pinfo, tree)
    return false  -- Don't automatically activate
end)

-- Allow manual decode-as selection
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add_for_decode_as(gsmtapv3_proto)