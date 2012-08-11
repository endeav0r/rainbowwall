-- tracks TPC Connections

package.cpath = package.cpath .. ";../?.so"
require("lrw")

-- connections = {
-- {
--   client_addr .. server_addr .. client_port .. server_port =
--     {
--        status = "syn" || "syn ack" || "connected"
--        client_seq = client's seq
--        server_ack = server's seq
--
--        -- this data has been acknowledged by the recipient
--        data[forward|backward] = acknowledged data
--
--        -- this is the sequence number of the first byte of data in
--        -- data_noack. this should be nil if there is no data in
--        -- data_noack[direction]
--        seq_noack[forward|backward]
--
--        -- unacknowledged server data
--        data_noack[forward|backward]
--     }
-- }

connections = {}


function tcp_track (packet)

    -- auxiliary functions
    local function message (msg)
        print(packet:net_src(), packet:net_dst(), msg)
    end

    -- compensates for the fact that lua Numbers are doubles, but 
    -- TCP sequence numbers are unsigned integers
    local function seq_add (a, b)
        a = a + b
        if a >= 4294967296 then
            a = a - 4294967296
        end
        return a
    end
    
    local function seq_sub (a, b)
        local result = a - b
        if result < 0 then
            result = (a + 4294967296) - b
        end
        return result
    end
            
    
    local function table_contains (tab, item)
        for ti, t in pairs(tab) do
            if t == item then
                return true
            end
        end
        return false
    end

    -- not a tcp packet = return
    local success, proto = pcall(function() return packet:trans_proto() end)
    if not success then
        return
    elseif proto ~= "tcp" then
        return
    end
    
    local flags = packet:tcp_flags()
    
    -- get connection
    -- we treat forward as client -> server
    -- and backward as server -> client
    local forward  = packet:net_src() .. packet:net_dst() ..
                     packet:trans_port_src() .. packet:trans_port_dst()
    local backward = packet:net_dst() .. packet:net_src() ..
                     packet:trans_port_dst() .. packet:trans_port_src()
    
    local connection = connections[forward]
    local direction  = forward -- variable to track direction
    if connection == nil then
        connection = connections[backward]
        direction  = backward
    end
    
    -- connection doesn't exist, initial syn
    if connection == nil then
        if flags[1] == "syn" then
            message("syn")
            connections[forward] = {status     = "syn",
                                    data       = {},
                                    seq_noack  = {},
                                    data_noack = {}}
            -- set client seq
            connections[forward]["client_seq"] = packet:tcp_seq()
        end

    -- connection at syn, looking for ack
    elseif connection["status"] == "syn" then
        -- is this the response in the right direction
        if direction = backward then
            -- syn ack?
            -- ack should equal client_seq + 1
            if table_contains(flags, "ack") and 
               table_contains(flags, "syn") and
               packet:tcp_ack() == seq_add(connection["client_seq"], 1) then
                    connection["status"] = "syn ack"
                    message("syn ack")
                    connection["client_seq"] = packet:tcp_ack()
                    connection["server_seq"] = packet:tcp_seq()
            -- rst?
            elseif flags[1] == "rst" then
                message("rst")
            end
        -- is this another syn?
        else
            if flags[1] == "syn" then
                message("dup syn")
            end
        end
        
    -- connection at syn ack, looking for ack
    elseif connection["status"] == "syn ack" then
        -- is this the response in the right direction
        -- ack should be server_seq + 1
        if direction = forward and
           table_contains(flags, "ack") and
           packet:tcp_ack() == seq_add(connection["server_seq"], 1) then
            connection["status"] = "connected"
            message("connected")
            connection["client_seq"] = packet:tcp_seq()
            connection["server_seq"] = packet:tcp_ack()
        end
    
    -- connection is established
    elseif connection["status"] == "connected" then
        -- if we have data, add it to noack queue
        local data = packet:data()
        if #data > 0 then
            -- make sure seq_noack is set appropriately
            if connection["seq_noack"][direction] == nil then
                connection["seq_noack"][direction] = connection:tcp_seq()
            end
            connection["data_noack"][direction] =
                             connection["data_noack"][direction] .. data
        end
        
        if table_contains(flags, "ack") then
            -- is there data to be acked ?
            if #connection.data_noack.data > 0 then
                -- how much of the data are we acking
                if
            end
            -- 
        
        if table_contains(flags, "rst") then
        
        end
    end
end



capture = lrw_capture_t.new()

while true do
    local success, packet = pcall(function () return capture:recv() end)
    if success then
        tcp_track(packet)
    end
end
