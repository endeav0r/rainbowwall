#!/usr/bin/luajit

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
        break
    end
    
    -- We are interested in tcp packets only.
    -- This call will normally through errors if the network protocol
    -- can't support TCP (think ARP), but we don't care about that so
    -- throw the errors away.
    local success, errmsg = pcall(function () return packet:trans_proto() == "tcp" end)
    if success and errmsg then
    
        -- Destination port is 80
        if packet:trans_port_dst() == 80 then
            local data = packet:data()
            -- Regex match the GET http header and Host http header lines.
            local url = string.match(data, "GET (.-) HTTP")
            -- If we matched the url header line, print it out.
            if url then
                local host = string.match(data, "Host: (.-)\r\n")
                print(packet:net_src() .. " " .. host .. url)
            end
            
        end
        
    end
    
end
