#!/usr/bin/lua

function execute_try (command)
    print('trying: ' .. command)
    return os.execute(command)
end

function execute (command)
    print(command)
    local status = os.execute(command)
    if status ~= 0 then 
        os.exit(status)
    end
end

HEADERS = {}
HEADERS['lua.h'] = {'', 'lua51/', 'lua50/'}
HEADERS['lauxlib.h'] = {'', 'lua51/', 'lua50/'}
HEADERS['lualib.h'] = {'', 'lua51/', 'lua50/'}

HEADER_PATHS = {}

for filename, paths in pairs(HEADERS) do
    header_found = false
    for i,path in pairs(paths) do
        local command = 'echo "#include <' .. path .. filename .. '>" | '
        command = command .. 'gcc -x c -c - -o /dev/null'
        if execute_try(command) == 0 then
            print('found ' .. path .. filename)
            table.insert(HEADER_PATHS, '#include <' .. path .. filename .. '>\n')
            header_found = true
            break
        end
    end
    if not header_found then
        print('could not find header file: ' .. filename)
        os.exit(1)
    end
end

-- no more
--fh = io.open('src/config.h', 'w')
--fh:write(table.concat(HEADER_PATHS, '\n'))
--fh:close()

deps = {'packet', 'net', 'trans', 'arp', 'icmp', 'capture', 'pcap'}
dep_objs = {}

for di, dep in pairs(deps) do
    execute("gcc -O2 -c -fpic -Wall -o src/" .. dep .. ".o src/" .. dep .. ".c")
    table.insert(dep_objs, 'src/' .. dep .. '.o')
end

execute("gcc -O2 -Wall -lpcap src/socket_dump.c -o socket_dump " .. 
        table.concat(dep_objs, " "))
        
execute("gcc -O2 -Wall -lpcap src/checksum_test.c -o checksum_test " .. 
        table.concat(dep_objs, " "))

execute("gcc -O2 -shared -lpcap -fpic -o lrw.so src/lrw.c -lluajit-5.1 " .. 
        table.concat(dep_objs, " "))
