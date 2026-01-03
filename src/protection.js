// ============================================================
// 🛡️ PROTECTION MODULE v5.0.0 - MAXIMUM SECURITY
// Multi-Layer Protection: XOR + Custom Base64 + Obfuscation
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

    // Generate 50+ random variable names
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
    
    // Generate junk functions
    const junkFunctions = [];
    for (let i = 0; i < 10; i++) {
        const junkName = randomVar('_junk');
        junkFunctions.push(`
    local function ${junkName}(${randomVar('a')}, ${randomVar('b')})
        local ${randomVar('x')} = ${Math.floor(Math.random() * 1000)}
        for ${randomVar('i')} = 1, ${randomVar('x')} do
            ${randomVar('x')} = ${randomVar('x')} * ${Math.random().toFixed(4)}
        end
        return ${randomVar('x')}
    end`);
    }
    
    const whitelistStr = whitelistUserIds.join(', ');

    // Generate protected script
    const protectedScript = `-- 🛡️ Protected Script v5.0.0
${junkFunctions.slice(0, 3).join('\n')}

local ${v.main} = (function()
    local _ENV = getfenv and getfenv() or _ENV or _G
    local game = game
    local pcall = pcall
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
    local HWID = nil
    
    ${junkFunctions.slice(3, 5).join('\n')}
    
    local function ${v.xor}(${v.data}, ${v.config})
        local ${v.result} = {}
        for ${v.index} = 1, #${v.data} do
            local ${v.temp} = string.byte(${v.data}, ${v.index})
            local ${v.offset} = string.byte(${v.config}, ((${v.index} - 1) % #${v.config}) + 1)
            table.insert(${v.result}, string.char(bit32.bxor(${v.temp}, ${v.offset})))
        end
        return table.concat(${v.result})
    end
    
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
    
    ${junkFunctions.slice(5, 7).join('\n')}
    
    local function ${v.decrypt}(${v.data}, ${v.config})
        local ${v.temp} = ${v.base64}(${v.data})
        return ${v.xor}(${v.temp}, ${v.config})
    end
    
    local ${v.context} = {
        endpoint = { d = "${strings.banEndpoint.data}", k = "${strings.banEndpoint.key}" },
        session = { d = "${strings.sessionToken.data}", k = "${strings.sessionToken.key}" },
        master = { d = "${strings.xorKey.data}", k = "${strings.xorKey.key}" }
    }
    
    local BAN_ENDPOINT = ${v.decrypt}(${v.context}.endpoint.d, ${v.context}.endpoint.k)
    local SESSION_TOKEN = ${v.decrypt}(${v.context}.session.d, ${v.context}.session.k)
    local MASTER_KEY = ${v.decrypt}(${v.context}.master.d, ${v.context}.master.k)
    local ${v.whitelist} = {${whitelistStr}}
    
    ${junkFunctions.slice(7, 9).join('\n')}
    
    local function ${v.validate}()
        if #${v.whitelist} == 0 then return false end
        for ${v.index}, ${v.temp} in ipairs(${v.whitelist}) do
            if LocalPlayer.UserId == ${v.temp} then return true end
        end
        return false
    end
    
    local function ${v.guard}()
        local ${v.flag} = false
        pcall(function()
            local ${v.temp} = {tostring(pcall), tostring(loadstring), tostring(game.HttpGet)}
            for ${v.index}, ${v.data} in ipairs(${v.temp}) do
                if ${v.data}:lower():find("hooked") or ${v.data}:lower():find("detour") then
                    ${v.flag} = true
                    break
                end
            end
        end)
        return not ${v.flag}
    end
    
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
                Title = "⛔", Text = ${v.data}, Duration = 5
            })
        end)
        
        wait(0.3)
        pcall(function()
            LocalPlayer:Kick("\\n⛔ BANNED\\n\\n" .. ${v.data})
        end)
    end
    
    ${junkFunctions[9]}
    
    local ${v.tools} = {
        _G = {
            "Dex", "DEX", "DexV2", "DexV3", "DexV4", "DexExplorer",
            "DarkDex", "DarkDexV3", "Dark_Dex",
            "InfiniteYield", "Infinite_Yield", "IY_LOADED", "IY",
            "Hydroxide", "HydroxideUI", "HYDROXIDE_LOADED",
            "SimpleSpy", "SimpleSpyExecuted", "SimpleSpy_Loaded",
            "RemoteSpy", "Remote_Spy", "REMOTESPY_LOADED",
            "BTool", "BTool_Loaded", "BTools",
            "F3X", "F3X_Loaded", "F3XTOOLS",
            "UnnamedESP", "ESP_LOADED", "ESP",
            "ScriptDumper", "SCRIPTDUMP"
        },
        gui = {
            "Dex", "DexV3", "DexV4", "DarkDex", "DarkDexV3",
            "InfiniteYield", "Infinite Yield", "IY",
            "Hydroxide", "SimpleSpy", "RemoteSpy", "Remote Spy",
            "BTool", "BTools", "F3X", "Unnamed ESP", "ESP"
        }
    }
    
    local function ${v.detect}()
        local ${v.result} = {}
        
        for ${v.index}, ${v.data} in ipairs(${v.tools}._G) do
            pcall(function()
                local ${v.temp} = rawget(_G, ${v.data})
                if ${v.temp} ~= nil and (type(${v.temp}) == "table" or type(${v.temp}) == "boolean") then
                    table.insert(${v.result}, ${v.data})
                end
            end)
        end
        
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
        
        pcall(function()
            for ${v.index}, ${v.data} in ipairs(${v.tools}.gui) do
                if CoreGui:FindFirstChild(${v.data}) or CoreGui:FindFirstChild(${v.data}, true) then
                    local ${v.temp} = ${v.data} .. "_UI"
                    if not table.find(${v.result}, ${v.temp}) then
                        table.insert(${v.result}, ${v.temp})
                    end
                end
            end
            
            for ${v.index}, ${v.temp} in pairs(CoreGui:GetChildren()) do
                if ${v.temp}:IsA("ScreenGui") then
                    local ${v.data} = ${v.temp}.Name:lower()
                    if ${v.data}:match("dex") or ${v.data}:match("infinite") or
                       ${v.data}:match("hydroxide") or ${v.data}:match("spy") then
                        if not table.find(${v.result}, ${v.temp}.Name) then
                            table.insert(${v.result}, ${v.temp}.Name)
                        end
                    end
                end
            end
        end)
        
        pcall(function()
            if LocalPlayer and LocalPlayer.PlayerGui then
                for ${v.index}, ${v.data} in ipairs(${v.tools}.gui) do
                    if LocalPlayer.PlayerGui:FindFirstChild(${v.data}, true) then
                        local ${v.temp} = ${v.data} .. "_PGUI"
                        if not table.find(${v.result}, ${v.temp}) then
                            table.insert(${v.result}, ${v.temp})
                        end
                    end
                end
            end
        end)
        
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
    
    local ${v.chunks} = {
        ${chunks.map((chunk, i) => `[${i + 1}] = "${chunk}"`).join(',\n        ')}
    }
    
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
    
    local function ${v.run}()
        if not ${v.guard}() then
            ${v.kick}("Security: Hook detected", {"Hook_Detected"})
            return false
        end
        
        if ${v.validate}() then
            warn("[🛡️] Developer mode")
            local ${v.temp} = ${v.decode}()
            if ${v.temp} and #${v.temp} > 0 then
                local ${v.loader} = loadstring or load
                if ${v.loader} then
                    local ${v.result} = ${v.loader}(${v.temp})
                    if ${v.result} then
                        pcall(${v.result})
                        return true
                    end
                end
            end
            return false
        end
        
        local ${v.temp} = ${v.detect}()
        if #${v.temp} > 0 then
            local ${v.data} = table.concat(${v.temp}, ", ")
            ${v.kick}("Tools: " .. ${v.data}, ${v.temp})
            return false
        end
        
        local ${v.data} = ${v.decode}()
        if ${v.data} and #${v.data} > 0 then
            local ${v.loader} = loadstring or load
            if not ${v.loader} then return false end
            
            local ${v.result}, ${v.temp} = ${v.loader}(${v.data})
            if not ${v.result} then return false end
            
            local ${v.flag}, ${v.config} = pcall(${v.result})
            return ${v.flag}
        end
        
        return false
    end
    
    local function ${v.loop}()
        if ${v.validate}() then return end
        spawn(function()
            while wait(12) do
                if not ${v.guard}() then
                    ${v.kick}("Runtime: Hook", {"Hook_Runtime"})
                    break
                end
                
                local ${v.temp} = ${v.detect}()
                if #${v.temp} > 0 then
                    ${v.kick}("Runtime: " .. table.concat(${v.temp}, ", "), ${v.temp})
                    break
                end
            end
        end)
    end
    
    ${v.loop}()
    return ${v.run}
end)()

local ${v.result} = ${v.main} and ${v.main}()
${v.main} = nil
${v.result} = nil
collectgarbage("collect")
collectgarbage("collect")
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
