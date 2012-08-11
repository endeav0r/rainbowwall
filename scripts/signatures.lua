#!/usr/bin/luajit

local SIGNATURES = {
    {"png", string.char(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)},
    {"zip", string.char(0x50, 0x4B, 0x03, 0x04)},
    {"gif", "GIF87a"},
    {"gif", "GIF89a"},
    {"html", "<html"},
    {"html", "<HTML"},
    {"jpeg", string.char(0xFF, 0xD8, 0xFF, 0xE0)},
    {"jpeg", string.char(0xFF, 0xD8, 0xFF, 0xE1)},
    {"jpeg", string.char(0xFF, 0xD8, 0xFF, 0xE8)},
}

-- By default, lrw.so builds in the directory beneath this one.
package.cpath = package.cpath .. ";../?.so"

-- Bring the lrw functionality in to this lua script.
require('lrw')

-- Start capturing.
local capture = lrw_capture_t.new()

-- This function allows us to print things out a bit nicer.
local IP_ADDRESS_ALIGN_WIDTH = 16
function align_white_append (s, length)
    return s .. string.rep(" ", length - #s)
end

while true do
    -- If capture:recv throws an error, print it out and break.
    -- This should only happen if it can't figure out the network layer
    -- protocol, though if you get RW_PACKET_ERR_SIZE, then you're
    -- throwing around frames bigger than rainbowwall can handle. Check
    -- RW_PACKET_FRAME_LEN in packet.h
    local success, packet = pcall(function () return capture:recv() end)
    if not success then
        print(packet)
    end
    
    -- We are interested in tcp/udp packets only
    local success, proto = pcall(function() return packet:trans_proto() end)
    if success and (proto =="tcp" or proto == "udp") then
        local data = packet:data()
        
        for si, signature in pairs(SIGNATURES) do
            if string.find(data, signature[2]) ~= nil then
                print(align_white_append(packet:net_src(), IP_ADDRESS_ALIGN_WIDTH)
                      .. " => " .. align_white_append(packet:net_dst(), IP_ADDRESS_ALIGN_WIDTH)
                       .. " " .. signature[1])
            end
        end
        
    end
end
