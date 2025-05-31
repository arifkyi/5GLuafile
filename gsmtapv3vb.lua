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
    if gsmtap_length > hdr_len_bytes then
        local payload_len = gsmtap_length - hdr_len_bytes
        subtree:add(fields.payload, gsmtap_buffer(hdr_len_bytes, payload_len))
        
        -- Try to dissect the payload based on type
        local payload_buffer = gsmtap_buffer(hdr_len_bytes, payload_len):tvb()
        
        -- Get dissector information
        local dissector_info = get_dissector_info(msg_type, sub_type)
        
        if dissector_info then
            -- Setup pinfo for specific dissectors if needed
            if dissector_info.setup then
                dissector_info.setup(pinfo, sub_type)
            end
            
            -- Try multiple dissector names/variations
            local dissector_variants = {dissector_info.name}
            
            -- Add specific channel variants for NR-RRC
            if msg_type == 0x0503 then  -- NR RRC
                -- Map subtypes to specific dissector names
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
                
                -- Add specific dissectors for this subtype
                if nr_rrc_dissectors[sub_type] then
                    for _, dissector_name in ipairs(nr_rrc_dissectors[sub_type]) do
                        table.insert(dissector_variants, dissector_name)
                    end
                end
                
                -- Also add additional common NR-RRC dissectors that might be relevant
                table.insert(dissector_variants, "nr-rrc.sbcch.sl.bch")
                table.insert(dissector_variants, "nr-rrc.scch")
                table.insert(dissector_variants, "nr-rrc.ueradiopaginginformation")
                table.insert(dissector_variants, "nr-rrc.ueradioaccesscapabilityinformation")
                table.insert(dissector_variants, "nr-rrc.rrc_reconf")
                table.insert(dissector_variants, "nr-rrc.uemrdccapability")
                table.insert(dissector_variants, "nr-rrc.uennrcapability")
                table.insert(dissector_variants, "nr-rrc.radiobearerconfig")
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
                    local result = subdissector:call(payload_buffer, pinfo, tree)
                    if result and result > 0 then
                        dissector_found = true
                        break
                    end
                end
            end
            
            -- If no specific dissector worked, try a more generic approach
            if not dissector_found then
                -- For debugging: try to find available dissectors
                local dissector_table = DissectorTable.get("wtap_encap")
                if dissector_table then
                    -- This is just for information - actual dissection might need different approach
                end
            end
        end
        
        -- Special handling for specific payload types that may need custom dissection
        if msg_type == 0x0503 and sub_type == 0x0006 then  -- NR RRC PCCH
            -- For PCCH messages, we know the structure starts with the message choice
            -- This could be enhanced to provide more detailed parsing if needed
            local payload_tree = tree:add("NR-RRC PCCH Payload Analysis")
            if payload_len > 0 then
                local first_byte = gsmtap_buffer(hdr_len_bytes, 1):uint()
                payload_tree:add_expert_info(PI_NOTE, PI_CHAT, 
                    string.format("PCCH message starts with: 0x%02x", first_byte))
            end
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