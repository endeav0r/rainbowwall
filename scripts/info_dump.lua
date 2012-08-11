#!/usr/bin/luajit

package.cpath = package.cpath .. ";../?.so"

print("require lrw")

require('lrw')

print("starting capture interface")

capture = lrw_capture_t.new()

print("capture interface created")

function align_white_append (s, length)
    return s .. string.rep(" ", length - #s)
end

while true do
    local has_data = false
    
    -- if capture:recv throws an error, print it out and break
    local success, packet = pcall(function () return capture:recv() end)
    if not success then
        print(packet)
        break
    end
    
    local line = ''
    
    -- data
    -------------------------------
    -- this is boring
    --line = packet:eth_src() .. " => " .. 
    --       packet:eth_dst()
    --line = line .. " | "
    
    -- net
    -------------------------------
    
    local success, errmsg = pcall(function () return packet:net_proto() end)
    if not success then
        print(errmsg)
    
    -- ip packets just have more fun
    elseif packet:net_proto() == "ipv4" or packet:net_proto() == "ipv6" then
        line = align_white_append(packet:net_src(), 15) .. " => " .. 
               align_white_append(packet:net_dst(), 15) .. " "
    
        -- transport
        -------------------------------
        
        -- packet:trans_proto() will throw an error if this transport
        -- layer protocol is unknown. we need to catch that
        local success, errmsg = pcall(function () return packet:trans_proto() end)
        if not success then
            line = line .. "| error: " .. errmsg
        else
            line = line .. "| " ..  packet:trans_proto() .. " "
            
            -- icmp type
            if packet:trans_proto() == "icmp" then
                line = line .. packet:icmp_type()
            end
            
            -- show off some tcp flags and seq/ack numbers
            if packet:trans_proto() == "tcp" then
                line = line .. "[" .. table.concat(packet:tcp_flags(), " ") .. "] "
                line = line .. "{" .. packet:tcp_seq() .. "/" .. packet:tcp_ack() .. "} "
            end
            
            -- src_prt => dst_port
            if packet:trans_proto() == "tcp" or packet:trans_proto() == "udp" then
                line = line .."(" .. 
                       packet:trans_port_src() .. " => " .. 
                       packet:trans_port_dst() .. ") "
                -- we can grab data. show the size of data in this packet       
                local data = packet:data()
                line = line .. "| " .. #data
            end
        end
    elseif packet:net_proto() == "arp" then
        line = line .. "arp [" .. packet:arp_opcode() .. "]"
    else
        line = line .. packet:net_proto()
    end
    
    print(line)
end
