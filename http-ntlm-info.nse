
--
-- Extract information from NTLM enabled HTTP services.
-- 
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author = "Jonas Vestberg"
--
-- Version 0.1
-- Revisions
-- 2013-04-30 - v0.1 - Published on github.com
--     

local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local base64 = require "base64"
local shortport = require "shortport"

local ntlminfo = require "ntlminfo"

author = "Jonas Vestberg"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {}

portrule = shortport.http

local PATH = stdnse.get_script_args(SCRIPT_NAME .. ".path")
local SOURCE = stdnse.get_script_args(SCRIPT_NAME .. ".source")
local DOMAIN = stdnse.get_script_args(SCRIPT_NAME .. ".domain")

action = function(host, port)

	local path = PATH or '/'
	local wks = SOURCE or 'TEST'
	local domain = SOURCE or 'TEST'

	local ntlm_type1 = base64.enc(make_ntlm_nego(wks,domain))

	stdnse.print_debug('Sending HTTP request with HTTP header "Authorization: '..ntlm_type1..'".')

	local options = {
		bypass_cache = true,
		header = {
			["Authorization"] = 'NTLM '..ntlm_type1
		}
	}

	local res = http.get(host, port, path, options)

	local www_auth = res.header['www-authenticate']

	if www_auth == nil then
		stdnse.print_debug('No WWW-Authenticate header in response')
		return
	end
	stdnse.print_debug('Recieved HTTP response header "WWW-Authenticate: '..www_auth..'" (multiple lines are merged by http-library).')

	local re = pcre.new('NTLM [a-zA-Z0-9+/=]+',0,'C')
	local i,j = re:match(www_auth,0,0)

	if i == nil then
		stdnse.print_debug('HTTP response header WWW-Authenticate does not contain a NTLM challenge.')
		return
	end

	local msg2 = string.sub(www_auth,i+5,j)
	stdnse.print_debug('NTLM challenge from server (base64-encoded): '..msg2)

	local targetinfo = parse_ntlm_chall(base64.dec(msg2))

	local result = format_ntlm_info(targetinfo)

	return stdnse.format_output(true, result)

end
