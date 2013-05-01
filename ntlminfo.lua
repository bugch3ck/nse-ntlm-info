
--
-- Library for creating and parsing NTLM messages.
-- Ported to lua from the python-ntlm project https://code.google.com/p/python-ntlm/
-- 
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author = "Jonas Vestberg"
--
-- Version 0.2
-- Revisions
-- 2013-04-30 - v0.1 - Published to github.com
-- 2013-05-01 - v0.2 - Fixed timestamp issue on 32-bit systems.
--     

local bin = require "bin"
local stdnse = require "stdnse"
local table = require "table"

NTLM_NegotiateUnicode                =  0x00000001
NTLM_NegotiateOEM                    =  0x00000002
NTLM_RequestTarget                   =  0x00000004
NTLM_Reserved10                      =  0x00000008
NTLM_NegotiateSign                   =  0x00000010
NTLM_NegotiateSeal                   =  0x00000020
NTLM_NegotiateDatagram               =  0x00000040
NTLM_NegotiateLanManagerKey          =  0x00000080
NTLM_Reserved9                       =  0x00000100
NTLM_NegotiateNTLM                   =  0x00000200
NTLM_NegotiateNTOnly                 =  0x00000400 -- NTLM_Reserved8 in spec
NTLM_Anonymous                       =  0x00000800
NTLM_NegotiateOemDomainSupplied      =  0x00001000
NTLM_NegotiateOemWorkstationSupplied =  0x00002000
NTLM_Unknown7                        =  0x00004000
NTLM_NegotiateAlwaysSign             =  0x00008000
NTLM_TargetTypeDomain                =  0x00010000
NTLM_TargetTypeServer                =  0x00020000
NTLM_TargetTypeShare                 =  0x00040000 -- NTLM_Reserved6 in spec
NTLM_NegotiateExtendedSecurity       =  0x00080000
NTLM_NegotiateIdentify               =  0x00100000
NTLM_Reserved5                       =  0x00200000
NTLM_RequestNonNTSessionKey          =  0x00400000
NTLM_NegotiateTargetInfo             =  0x00800000
NTLM_Reserved4                       =  0x01000000
NTLM_NegotiateVersion                =  0x02000000
NTLM_Reserved3                       =  0x04000000
NTLM_Reserved2                       =  0x08000000
NTLM_Reserved1                       =  0x10000000
NTLM_Negotiate128                    =  0x20000000
NTLM_NegotiateKeyExchange            =  0x40000000
NTLM_Negotiate56                     =  0x80000000

NTLM_MsvAvEOL             = 0 -- Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
NTLM_MsvAvNbComputerName  = 1 -- The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvNbDomainName    = 2 -- The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvDnsComputerName = 3 -- The server's Active Directory DNS computer name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsDomainName   = 4 -- The server's Active Directory DNS domain name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsTreeName     = 5 -- The server's Active Directory (AD) DNS forest tree name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvFlags           = 6 -- A field containing a 32-bit value indicating server or client configuration. 0x00000001: indicates to the client that the account authentication is constrained. 0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
NTLM_MsvAvTimestamp       = 7 -- A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<12>
NTLM_MsvAvSingleHost      = 8 -- A Restriction_Encoding structure (section 2.2.2.2). The Value field contains a structure representing the integrity level of the security principal, as well as a MachineID created at computer startup to identify the calling machine. <13>

NTLM_MsvAvMaxKnown        = NTLM_MsvAvSingleHost -- used while parsing

NTLM_TYPE1_FLAGS = bit32.bor(
	NTLM_NegotiateUnicode, -- Lua does not handle Unicode well (workaround with fix_unicode)
	NTLM_NegotiateOEM,
	NTLM_RequestTarget,
	NTLM_NegotiateNTLM,
	NTLM_NegotiateOemDomainSupplied,
	NTLM_NegotiateOemWorkstationSupplied,
	NTLM_NegotiateAlwaysSign,
	NTLM_NegotiateExtendedSecurity,
	NTLM_NegotiateVersion,
	NTLM_Negotiate128,
	NTLM_Negotiate56 )

function make_ntlm_nego(w,d)

	local payload_off = 40
	local protocol = 'NTLMSSP\0'

	local type = bin.pack('<I',1) -- TYPE1
	local flags = bin.pack('<I',NTLM_TYPE1_FLAGS)

	local workstation = w.upper(w)
	local domainname = d.upper(d)

	local workstation_len = bin.pack('<S',string.len(w))
	local workstation_max = bin.pack('<S',string.len(w))
	local workstation_off = bin.pack('<I',payload_off)
	payload_off = payload_off + string.len(w)

	local domainname_len = bin.pack('<S',string.len(d))
	local domainname_max = bin.pack('<S',string.len(d))
	local domainname_off = bin.pack('<I',payload_off)
	payload_off = payload_off + string.len(d)

	local version_major = bin.pack('<C',5)
	local version_minor = bin.pack('<C',1)
	local version_build = bin.pack('<S',2600)
	local version_res1 = bin.pack('<C',0)
	local version_res2 = bin.pack('<C',0)
	local version_res3 = bin.pack('<C',0)
	local ntlm_revision = bin.pack('<C',15)
	
	local msg1 = protocol .. type .. flags
		.. domainname_len .. domainname_max .. domainname_off
		.. workstation_len .. workstation_max .. workstation_off
		.. version_major .. version_minor .. version_build
		.. version_res1 .. version_res2 .. version_res3
		.. ntlm_revision
		.. workstation .. domainname

	return msg1
end

local function fix_unicode(s)

	-- Return 0 for nil.
	if not s then return 0 end

	-- Remove every 2nd character in the Unicode string. 
	local i
	local r = ''

	for i=1,#s,2 do
		r = r..s:sub(i,i) 
	end

	return r
end

local id_name_map = {
	[NTLM_MsvAvNbComputerName]  = 'NbComputerName',
	[NTLM_MsvAvNbDomainName]    = 'NbDomainName',
	[NTLM_MsvAvDnsComputerName] = 'DnsComputerName',
	[NTLM_MsvAvDnsDomainName]   = 'DnsDomainName',
	[NTLM_MsvAvDnsTreeName]     = 'DnsTreeName',
	[NTLM_MsvAvFlags]           = 'Flags',
	[NTLM_MsvAvTimestamp]       = 'Timestamp',
	[NTLM_MsvAvSingleHost]      = 'SingleHost'
}

local function map_av_id(id)
	local id_str

	if (id < NTLM_MsvAvMaxKnown) then
		id_str = id_name_map[id]
	else
		id_str = 'Unknown ('..id..')'
	end

	return id_str
end

function parse_ntlm_chall (msg2)

	local protocol, msgtype, next_off
	local flags, challenge
	local target, target_len, target_max, target_off
	local version_major, version_minor, version_build
	local version, info

	protocol = msg2:sub(1,8)
	next_off,msgtype = bin.unpack('<I',msg2,9)

	-- TODO assert on protocol and type

	next_off,target_len = bin.unpack('<S',msg2,13)
	next_off,target_max = bin.unpack('<S',msg2,15)
	next_off,target_off = bin.unpack('<I',msg2,17)

	next_off,flags = bin.unpack('<I',msg2,21)

	target = msg2:sub(target_off+1,target_off+target_len)

	if bit32.band(flags, NTLM_NegotiateUnicode) then
		target = fix_unicode(target)
	end

	challenge = msg2:sub(25,32)

	if bit32.band(flags, NTLM_NegotiateVersion) then
		local v1,v2,v3
		next_off,v1 = bin.unpack('<C',msg2,49)
		next_off,v2 = bin.unpack('<C',msg2,50)
		next_off,v3 = bin.unpack('<S',msg2,51)
		version = {v1,v2,v3}
	end

	if bit32.band(flags, NTLM_NegotiateTargetInfo) then

		local info_len, info_max, info_off, infodata
		local av_id, av_len, av_val
		info = {}
		
		next_off,info_len = bin.unpack('<S',msg2,41)
		next_off,info_max = bin.unpack('<S',msg2,43)
		next_off,info_off = bin.unpack('<I',msg2,45)

		infodata = msg2:sub(info_off+1,info_off+info_len)

		local i
		i=1 
		while i<=info_len do

			next_off,av_id = bin.unpack('<S',infodata,i)
			next_off,av_len = bin.unpack('<S',infodata,next_off)
			av_val = infodata:sub(next_off,next_off+av_len-1)
			i = i+4+av_len

			if av_id>0 then
				
				if av_id == NTLM_MsvAvTimestamp then
					local a,b
					a,b = bin.unpack('<L',av_val)
					-- NOTE stdnse.date_to_timestamp / os.date can't handle dates older than 1901-12-13H21:45:52 on 32 bit systems.
					-- This returns nil on a 32-bit system --> local filetime_base = stdnse.date_to_timestamp({year=1601,month=1,day=1,hour=0,min=0,sec=0})
					local filetime_base = -11644473600 -- timestamp for 1601-01-01T00:00:00
					av_val = stdnse.format_timestamp(filetime_base + b/10000000)
				elseif av_id == NTLM_MsvAvFlags then
					-- NOTE: Never seen, never tested.
					av_val = bin.unpack('<I',av_val)
					av_val = string.format('%0x',av_val)
				elseif av_id == NTLM_MsvAvSingleHost then
					-- NOTE: Never seen, never implemented.
					av_val = '(not parsed)'
				else
					-- parse string data (unicode, not null-terminated)
					av_val = fix_unicode(av_val)
				end
				info[map_av_id(av_id)] = av_val
			end
		end
	end

	local result = {}
	result['target'] = target
	result['flags'] = flags
	result['challenge'] = challenge
	result['version'] = version
	result['info'] = info

	return result
end

function format_ntlm_info(targetinfo)

	local response = {}
	table.insert(response,'Target: '..targetinfo['target'])
	table.insert(response,'Flags: '..stdnse.tobinary(targetinfo['flags']))
	table.insert(response,'Challenge: '..stdnse.tohex(targetinfo['challenge']))

	if targetinfo['version'] then
		local version_str
		version_str = string.format('%d.%d.%d',targetinfo['version'][1],targetinfo['version'][2],targetinfo['version'][3])
		table.insert(response,'Version: '..version_str)
	end

	if targetinfo['info'] then

		-- sort on keys

		local key, val, i
		local keys = {}
		local info = targetinfo['info']

		for key,val in pairs(info) do
			table.insert(keys,key)
		end

		table.sort(keys)

		-- create a table with "key: value".

		local infotable = {}
		infotable['name'] = 'Target Info:'

		for i=1,#keys do
			key = keys[i]
			table.insert(infotable,key..': '..info[key])
		end

		table.insert(response,infotable)
	end

	return response
end

