#!/usr/bin/luajit

package.cpath = package.cpath .. ";../?.so"

require('lrw')

local sourcecap = lrw_capture_t.new("eth0")
local destcap = lrw_capture_t.new("tap0")

function align_white_append (s, length)
    return s .. string.rep(" ", length - #s)
end

while true do
    local has_data = false
    
    -- if capture:recv throws an error, print it out and break
    local success, packet = pcall(function () return sourcecap:recv() end)
    if not success then
        print(packet)
        break
    end
    
    local success, errmsg = pcall(function () return packet:trans_proto() == "tcp" end)
    if success and errmsg then
    
        if packet:trans_port_src() == 80 then
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
