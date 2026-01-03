// ============================================================
// 🛡️ PROTECTION MODULE v5.0.1 - FIXED
// Fixed: collectgarbage issue & whitelist priority
// ============================================================

const crypto = require('crypto');

// ============================================================
// 🔧 UTILITY FUNCTIONS
// ============================================================

function randomString(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(6).toString('hex');
}

function xorEncrypt(str, key) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += String.fromCharCode(
            str.charCodeAt(i) ^ key.charCodeAt(i % key.length)
        );
    }
    return result;
}

function obfuscateString(str) {
    const key = randomString(16);
    const encrypted = xorEncrypt(str, key);
    const base64 = Buffer.from(encrypted).toString('base64');
    return { data: base64, key: key };
}

function customBase64Encode(str) {
    const standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const custom = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_';
    
    const base64 = Buffer.from(str).toString('base64');
    let result = '';
    
    for (let i = 0; i < base64.length; i++) {
        const idx = standard.indexOf(base64[i]);
        result += idx !== -1 ? custom[idx] : base64[i];
    }
    
    return result;
}

function generateChecksum(script) {
    return crypto.createHash('sha256').update(script).digest('hex').substring(0, 16);
}

// ============================================================
// 🔒 GENERATE PROTECTED SCRIPT
// ============================================================

function generateProtectedScript(originalScript, options = {}) {
    const {
        sessionToken = crypto.randomBytes(16).toString('hex'),
        timestamp = Date.now(),
        clientIP = 'unknown',
        hwid = null,
        playerId = null,
        banEndpoint = '',
        whitelistUserIds = []
    } = options;

    // Generate random variable names
    const v = {};
    const varNames = [
        'main', 'security', 'tools', 'detect', 'kick', 'decode', 
        'chunks', 'http', 'hwid', 'loop', 'run', 'result', 
        'whitelist', 'xor', 'base64', 'decrypt', 'verify',
        'guard', 'check', 'validate', 'execute', 'parse',
        'buffer', 'stream', 'cache', 'memory', 'processor',
        'handler', 'wrapper', 'loader', 'compiler', 'runtime',
        'env', 'context', 'scope', 'stack', 'heap',
        'register', 'pointer', 'offset', 'index', 'counter',
        'flag', 'state', 'status', 'config', 'data',
        'temp', 'util', 'helper', 'service', 'manager'
    ];
    
    varNames.forEach(name => {
        v[name] = randomVar('_');
    });

    // Generate XOR key
    const xorKey = randomString(32);
    
    // Split script into random-sized chunks
    const chunks = [];
    let position = 0;
    
    while (position < originalScript.length) {
        const chunkSize = Math.floor(Math.random() * 200) + 300;
        const chunk = originalScript.substring(position, position + chunkSize);
        const xored = xorEncrypt(chunk, xorKey);
        const encoded = customBase64Encode(xored);
        chunks.push(encoded);
        position += chunkSize;
    }
    
    // Obfuscate critical strings
    const strings = {
        banEndpoint: obfuscateString(banEndpoint),
        sessionToken: obfuscateString(sessionToken),
        xorKey: obfuscateString(xorKey)
    };
    
    // Generate junk functions (reduced to avoid detection)
    const junkFunctions = [];
    for (let i = 0; i < 5; i++) {
        const junkName = randomVar('_j');
        junkFunctions.push(`local function ${junkName}() return ${Math.floor(Math.random() * 1000)} end`);
    }
    
    const whitelistStr = whitelistUserIds.join(', ');

    // Generate protected script
    const protectedScript = `-- Protected Script v5.0.1
${junkFunctions.slice(0, 2).join('\n')}

local ${v.main} = (function()
    local game = game
    local pcall = pcall
    local xpcall = xpcall
    local type = type
    local table = table
    local string = string
    local math = math
    local bit32 = bit32
    local tick = tick
    local wait = task and task.wait or wait
    local spawn = task and task.spawn or spawn
    local pairs = pairs
    local ipairs = ipairs
    local loadstring = loadstring
    local rawget = rawget
    local setmetatable = setmetatable
    
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    
    local LocalPlayer = Players.LocalPlayer
    
    ${junkFunctions[2]}
    
    -- XOR Decryptor
    local function ${v.xor}(${v.data}, ${v.config})
        local ${v.result} = {}
        for ${v.index} = 1, #${v.data} do
            local ${v.temp} = string.byte(${v.data}, ${v.index})
            local ${v.offset} = string.byte(${v.config}, ((${v.index} - 1) % #${v.config}) + 1)
            table.insert(${v.result}, string.char(bit32.bxor(${v.temp}, ${v.offset})))
        end
        return table.concat(${v.result})
    end
    
    -- Custom Base64 Decoder
    local function ${v.base64}(${v.data})
        local ${v.cache} = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_'
        local ${v.stream} = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        local ${v.buffer} = ''
        
        for ${v.index} = 1, #${v.data} do
            local ${v.temp} = ${v.data}:sub(${v.index}, ${v.index})
            local ${v.offset} = ${v.cache}:find(${v.temp}, 1, true)
            ${v.buffer} = ${v.buffer} .. (${v.offset} and ${v.stream}:sub(${v.offset}, ${v.offset}) or ${v.temp})
        end
        
        ${v.buffer} = ${v.buffer}:gsub('[^'..${v.stream}..'=]', '')
        return (${v.buffer}:gsub('.', function(${v.temp})
            if (${v.temp} == '=') then return '' end
            local ${v.result}, ${v.flag} = '', (${v.stream}:find(${v.temp}) - 1)
            for ${v.counter} = 6, 1, -1 do 
                ${v.result} = ${v.result} .. (${v.flag} % 2 ^ ${v.counter} - ${v.flag} % 2 ^ (${v.counter} - 1) > 0 and '1' or '0') 
            end
            return ${v.result}
        end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(${v.temp})
            if (#${v.temp} ~= 8) then return '' end
            local ${v.result} = 0
            for ${v.counter} = 1, 8 do 
                ${v.result} = ${v.result} + (${v.temp}:sub(${v.counter}, ${v.counter}) == '1' and 2^(8-${v.counter}) or 0) 
            end
            return string.char(${v.result})
        end))
    end
    
    ${junkFunctions[3]}
    
    -- String Decryptor
    local function ${v.decrypt}(${v.data}, ${v.config})
        local ${v.temp} = ${v.base64}(${v.data})
        return ${v.xor}(${v.temp}, ${v.config})
    end
    
    -- Encrypted strings
    local ${v.context} = {
        endpoint = { d = "${strings.banEndpoint.data}", k = "${strings.banEndpoint.key}" },
        session = { d = "${strings.sessionToken.data}", k = "${strings.sessionToken.key}" },
        master = { d = "${strings.xorKey.data}", k = "${strings.xorKey.key}" }
    }
    
    local BAN_ENDPOINT = ${v.decrypt}(${v.context}.endpoint.d, ${v.context}.endpoint.k)
    local SESSION_TOKEN = ${v.decrypt}(${v.context}.session.d, ${v.context}.session.k)
    local MASTER_KEY = ${v.decrypt}(${v.context}.master.d, ${v.context}.master.k)
    
    -- Developer whitelist (PRIORITY CHECK)
    local WHITELIST_IDS = {${whitelistStr}}
    
    local function ${v.validate}()
        if #WHITELIST_IDS == 0 then return false end
        local myId = LocalPlayer.UserId
        for _, uid in ipairs(WHITELIST_IDS) do
            if myId == uid then
                return true
            end
        end
        return false
    end
    
    -- Check if developer IMMEDIATELY
    local IS_DEVELOPER = ${v.validate}()
    
    ${junkFunctions[4]}
    
    -- HWID getter
    local HWID = nil
    local function ${v.hwid}()
        if HWID then return HWID end
        pcall(function()
            HWID = (gethwid and gethwid()) or
                   (get_hwid and get_hwid()) or
                   (getexecutorname and getexecutorname() .. "_" .. tostring(LocalPlayer.UserId)) or
                   ("EX_" .. tostring(LocalPlayer.UserId))
        end)
        return HWID or "UNKNOWN"
    end
    
    -- HTTP request
    local function ${v.http}(${v.data})
        pcall(function()
            local ${v.temp} = (syn and syn.request) or (http and http.request) or 
                             request or (fluxus and fluxus.request) or http_request
            if ${v.temp} then
                ${v.temp}({
                    Url = BAN_ENDPOINT,
                    Method = "POST",
                    Headers = {["Content-Type"] = "application/json"},
                    Body = HttpService:JSONEncode(${v.data})
                })
            end
        end)
    end
    
    -- Kick & Ban
    local function ${v.kick}(${v.data}, ${v.config})
        pcall(function()
            if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
                ${v.http}({
                    hwid = ${v.hwid}(),
                    playerId = LocalPlayer.UserId,
                    playerName = LocalPlayer.Name,
                    reason = ${v.data},
                    toolsDetected = ${v.config} or {}
                })
            end
        end)
        
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ Banned",
                Text = ${v.data},
                Duration = 5
            })
        end)
        
        wait(0.5)
        pcall(function()
            LocalPlayer:Kick("⛔ BANNED\\n\\n" .. ${v.data})
        end)
    end
    
    -- Tool detection
    local ${v.tools} = {
        _G = {
            "Dex", "DEX", "DexV2", "DexV3", "DexV4",
            "DarkDex", "DarkDexV3",
            "InfiniteYield", "Infinite_Yield", "IY_LOADED", "IY",
            "Hydroxide", "HydroxideUI",
            "SimpleSpy", "RemoteSpy",
            "BTool", "F3X"
        },
        gui = {
            "Dex", "DexV3", "DarkDex",
            "InfiniteYield", "IY",
            "Hydroxide", "SimpleSpy", "RemoteSpy",
            "BTool", "F3X"
        }
    }
    
    local function ${v.detect}()
        local ${v.result} = {}
        
        -- Check _G
        for ${v.index}, ${v.data} in ipairs(${v.tools}._G) do
            pcall(function()
                local ${v.temp} = rawget(_G, ${v.data})
                if ${v.temp} ~= nil and (type(${v.temp}) == "table" or type(${v.temp}) == "boolean") then
                    table.insert(${v.result}, ${v.data})
                end
            end)
        end
        
        -- Check getgenv
        pcall(function()
            if getgenv then
                local ${v.env} = getgenv()
                for ${v.index}, ${v.data} in ipairs(${v.tools}._G) do
                    local ${v.temp} = rawget(${v.env}, ${v.data})
                    if ${v.temp} ~= nil and (type(${v.temp}) == "table" or type(${v.temp}) == "boolean") then
                        if not table.find(${v.result}, ${v.data}) then
                            table.insert(${v.result}, ${v.data})
                        end
                    end
                end
            end
        end)
        
        -- Check CoreGui (Most reliable)
        pcall(function()
            for ${v.index}, ${v.data} in ipairs(${v.tools}.gui) do
                if CoreGui:FindFirstChild(${v.data}) or CoreGui:FindFirstChild(${v.data}, true) then
                    local ${v.temp} = ${v.data} .. "_UI"
                    if not table.find(${v.result}, ${v.temp}) then
                        table.insert(${v.result}, ${v.temp})
                    end
                end
            end
        end)
        
        -- Check PlayerGui
        pcall(function()
            if LocalPlayer and LocalPlayer.PlayerGui then
                for ${v.index}, ${v.data} in ipairs(${v.tools}.gui) do
                    if LocalPlayer.PlayerGui:FindFirstChild(${v.data}, true) then
                        local ${v.temp} = ${v.data} .. "_PG"
                        if not table.find(${v.result}, ${v.temp}) then
                            table.insert(${v.result}, ${v.temp})
                        end
                    end
                end
            end
        end)
        
        -- Check shared
        pcall(function()
            if shared then
                if shared.IYPrefix or shared.InfiniteYield or shared.IY then
                    table.insert(${v.result}, "IY_Shared")
                end
                if shared.Hydroxide then
                    table.insert(${v.result}, "Hydroxide_Shared")
                end
            end
        end)
        
        return ${v.result}
    end
    
    -- Encrypted chunks
    local ${v.chunks} = {
        ${chunks.map((chunk, i) => `[${i + 1}] = "${chunk}"`).join(',\n        ')}
    }
    
    -- Master decoder
    local function ${v.decode}()
        local ${v.buffer} = {}
        for ${v.index}, ${v.data} in ipairs(${v.chunks}) do
            pcall(function()
                local ${v.temp} = ${v.base64}(${v.data})
                local ${v.result} = ${v.xor}(${v.temp}, MASTER_KEY)
                ${v.buffer}[${v.index}] = ${v.result}
            end)
        end
        return table.concat(${v.buffer})
    end
    
    -- Main execution
    local function ${v.run}()
        -- PRIORITY 1: Check if developer (SKIP ALL PROTECTION)
        if IS_DEVELOPER then
            warn("[Premium Loader] Developer mode - Protection bypassed")
            local ${v.temp} = ${v.decode}()
            if ${v.temp} and #${v.temp} > 0 then
                local ${v.loader} = loadstring or load
                if ${v.loader} then
                    local ${v.result}, ${v.err} = ${v.loader}(${v.temp})
                    if ${v.result} then
                        local ${v.ok}, ${v.msg} = pcall(${v.result})
                        if not ${v.ok} then
                            warn("[Premium Loader] Runtime error:", ${v.msg})
                        end
                        return ${v.ok}
                    else
                        warn("[Premium Loader] Compile error:", ${v.err})
                    end
                end
            end
            return false
        end
        
        -- PRIORITY 2: Tool detection for normal users
        local ${v.temp} = ${v.detect}()
        if #${v.temp} > 0 then
            local ${v.data} = table.concat(${v.temp}, ", ")
            warn("[Premium Loader] Tools detected:", ${v.data})
            ${v.kick}("Malicious tools: " .. ${v.data}, ${v.temp})
            return false
        end
        
        -- PRIORITY 3: Execute script
        local ${v.data} = ${v.decode}()
        if ${v.data} and #${v.data} > 0 then
            local ${v.loader} = loadstring or load
            if not ${v.loader} then
                warn("[Premium Loader] Loader unavailable")
                return false
            end
            
            local ${v.result}, ${v.err} = ${v.loader}(${v.data})
            if not ${v.result} then
                warn("[Premium Loader] Compile error:", ${v.err})
                return false
            end
            
            local ${v.flag}, ${v.msg} = pcall(${v.result})
            if not ${v.flag} then
                warn("[Premium Loader] Runtime error:", ${v.msg})
            end
            
            return ${v.flag}
        end
        
        return false
    end
    
    -- Runtime monitoring (only for non-developers)
    local function ${v.loop}()
        if IS_DEVELOPER then
            warn("[Premium Loader] Monitoring disabled for developer")
            return
        end
        
        spawn(function()
            while wait(15) do
                local ${v.temp} = ${v.detect}()
                if #${v.temp} > 0 then
                    local ${v.data} = table.concat(${v.temp}, ", ")
                    warn("[Premium Loader] Runtime detection:", ${v.data})
                    ${v.kick}("Runtime tools: " .. ${v.data}, ${v.temp})
                    break
                end
            end
        end)
    end
    
    -- Start monitoring
    ${v.loop}()
    
    -- Return executor
    return ${v.run}
end)()

-- Execute
local ${v.result} = ${v.main} and ${v.main}()

-- Cleanup (FIXED: safe collectgarbage)
${v.main} = nil
${v.result} = nil
pcall(function() collectgarbage("count") end)
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    generateChecksum,
    randomVar,
    xorEncrypt,
    obfuscateString
};
