protocol = Proto("goodix",  "Goodix Fingerprint Sensor Message Protocol")

cmd0 = ProtoField.uint8("goodix.cmd0", "cmd0", base.HEX, nil, 0xF0)
cmd1 = ProtoField.uint8("goodix.cmd1", "cmd1", base.HEX, nil, 0x0E)
len = ProtoField.uint16("goodix.len", "Length", base.DEC)
cksum = ProtoField.uint8("goodix.cksum", "Checksum", base.HEX)

ack_cmd = ProtoField.uint8("goodix.ack_cmd", "ACKed Command", base.HEX)
firmware_version = ProtoField.stringz("goodix.firmware_version", "Firmware Version")
enabled = ProtoField.bool("goodix.enabled", "Enabled")

mcu_state_image = ProtoField.bool("goodix.mcu_state.is_image_valid", "isImageValid", 8, nil, 0x01) -- Meaning unknown
mcu_state_tls = ProtoField.bool("goodix.mcu_state.is_tls_connected", "isTlsConnected", 8, nil, 0x02)
mcu_state_spi = ProtoField.bool("goodix.mcu_state.is_spi_send", "isSpiSend", 8, nil, 0x04) -- Meaning unknown
mcu_state_locked = ProtoField.bool("goodix.mcu_state.is_locked", "isLocked", 8, nil, 0x08) -- Meaning unknown

protocol.fields = {
   cmd0, cmd1, len, cksum,
   ack_cmd,
   firmware_version,
   enabled,
   mcu_state_image, mcu_state_tls, mcu_state_spi, mcu_state_locked
}

-- From log file, used as a fallback when the full cmd name is unknown
cmd0_names = {
   [0x0] = "NOP",
   [0x2] = "Ima",
   [0x3] = "FDT",
   [0x4] = "FF",
   [0x5] = "NAV",
   [0x6] = "Sle",
   [0x7] = "IDL",
   [0x8] = "REG",
   [0x9] = "CHIP",
   [0xA] = "OTHER",
   [0xB] = "MSG",
   [0xC] = "NOTI",
   [0xD] = "TLSCONN",
   [0xE] = "PROD",
   [0xF] = "UPFW",
}

function protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "Goodix"

   local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

   body_buf = buffer(3, buffer:len()-4):tvb()

   subtree:add_le(cmd0, buffer(0,1))
   subtree:add_le(cmd1, buffer(0,1))
   subtree:add_le(len, buffer(1,2)):append_text(" bytes (including checksum)")
   subtree:add_le(cksum, buffer(buffer:len()-1,1))

   cmd_val = buffer(0, 1):le_uint()
   from_host = pinfo.src == Address.ip("1.1.1.1")

   local cmd_subtree = tree:add(protocol, body_buf())

   cmd_name = string.format("%s.%x", cmd0_names[bit.rshift(cmd_val, 4)], bit.rshift(cmd_val%16, 1))

   if cmd_val == 0x00 then
      -- This packet has a fixed, non-standard checksum of 0x88
      -- It's purpose is unknown.
      cmd_name = "nop"
   elseif cmd_val == 0xB0 then
      cmd_name = "Ack"
      if not from_host then
         cmd_subtree:add_le(ack_cmd, body_buf(0, 1))
      end
   elseif cmd_val == 0xA8 then
      cmd_name = "Firmware Version"
      if not from_host then
         cmd_subtree:add_le(firmware_version, body_buf())
      end
   elseif cmd_val == 0x96 then
      cmd_name = "Enable Chip"
      if from_host then
         cmd_subtree:add_le(enabled, body_buf(0, 1))
      end
   elseif cmd_val == 0xae then
      cmd_name = "MCU State"
      if not from_host then
         cmd_subtree:add_le(mcu_state_image, body_buf(0, 1))
         cmd_subtree:add_le(mcu_state_tls, body_buf(0, 1))
         cmd_subtree:add_le(mcu_state_spi, body_buf(0, 1))
         cmd_subtree:add_le(mcu_state_locked, body_buf(0, 1))
      end
   end

   if from_host then
      summary = "Command: " .. cmd_name
   else
      summary = "Reply: " .. cmd_name
   end
   cmd_subtree.text = summary
   pinfo.cols.info = summary
end

DissectorTable.get("tls.port"):add(1, protocol)
