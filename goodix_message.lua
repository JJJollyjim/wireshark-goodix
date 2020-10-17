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

reset_flag_sensor = ProtoField.bool("goodix.reset_flag.sensor", "Reset Sensor", 8, nil, 0x01)
reset_flag_mcu = ProtoField.bool("goodix.reset_flag.mcu", "Soft Reset MCU", 8, nil, 0x02)
reset_flag_sensor_copy = ProtoField.bool("goodix.reset_flag.sensor_copy", "Reset Sensor (copy)", 8, nil, 0x04) -- Driver always sets this at the same time as reset_flag.sensor, firmware ignores this one

sensor_reset_success = ProtoField.bool("goodix.sensor_reset_success", "Sensor reset success") -- False if a timeout occours getting a response from the sensor
sensor_reset_number = ProtoField.uint16("goodix.sensor_reset_number", "Sensor reset number") -- Contents unknown, but it's a LE short sent if the sensor reset succeeds

reg_multiple = ProtoField.bool("goodix.sensor_reg.multiple", "Multiple addresses") -- Only false is used by driver, no dissection implemented for true
reg_address = ProtoField.uint16("goodix.sensor_reg.addr", "Base Address", base.HEX)
reg_len = ProtoField.uint8("goodix.sensor_reg.len", "Length")

pwrdown_scan_freq = ProtoField.uint16("goodix.powerdown_scan_frequency", "Powerdown Scan Frequecy")

protocol.fields = {
   cmd0, cmd1, len, cksum,
   ack_cmd,
   firmware_version,
   enabled,
   mcu_state_image, mcu_state_tls, mcu_state_spi, mcu_state_locked,
   reset_flag_sensor, reset_flag_mcu, reset_flag_sensor_copy,
   sensor_reset_success, sensor_reset_number,
   reg_multiple, reg_address, reg_len,
   pwrdown_scan_freq
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
      -- Its purpose is unknown -- REd firmware does nothing when it recieves one.
      cmd_name = "nop"
   elseif cmd_val == 0xB0 then
      cmd_name = "Ack"
      if not from_host then
         cmd_subtree:add_le(ack_cmd, body_buf(0, 1))
      end
   elseif cmd_val == 0xA2 then
      cmd_name = "Reset"

      if from_host then
          cmd_subtree:add_le(reset_flag_sensor, body_buf(0, 1))
          cmd_subtree:add_le(reset_flag_mcu, body_buf(0, 1))
          cmd_subtree:add_le(reset_flag_sensor_copy, body_buf(0, 1))
      else
         cmd_subtree:add_le(sensor_reset_success, body_buf(0, 1))
         cmd_subtree:add_le(sensor_reset_number, body_buf(1, 2))
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
   elseif cmd_val == 0x82 then
      cmd_name = "Read Sensor Register"

      if from_host then
         cmd_subtree:add_le(reg_multiple, body_buf(0, 1))
         cmd_subtree:add_le(reg_address, body_buf(1, 2))
         cmd_subtree:add_le(reg_len, body_buf(3, 1)):append_text(" bytes")
      else
         -- Reply is just the bytes requested
      end
   elseif cmd_val == 0xa6 then
      -- I believe OTP refers to one-time-programmable memory, which is written with calibration values at the factory

      cmd_name = "Read OTP"

      -- Request is empty, response is the OTP (32 bytes for my sensor model, I believe it differs with others)
   elseif cmd_val == 0x90 then
      cmd_name = "Upload Config"
   elseif cmd_val == 0x94 then
      cmd_name = "Set Powerdown Scan Frequency"
      -- I believe this is for a feature (POV/persistance of vision) where the sensor continues scanning while the laptop is asleep, and sends it to the laptop once it wakes up
      cmd_subtree:add_le(pwrdown_scan_freq, body_buf(0, 2)) -- Units unknown, though mine is 100, so ms would make sense?
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
