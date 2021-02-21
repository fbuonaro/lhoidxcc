local lhauth = {}

local cjson_decode = require( "cjson" ).decode
local cjson_encode = require( "cjson" ).encode
local resty_openidc_authenticate = require( "resty.openidc" ).authenticate

local HEADER_OP = "LHAUTH-OP"
local HEADER_USER = "LHAUTH-USER"

-- { op -> opts }
local opts_by_op = {}

local function check_opts( opts )
    assert( opts[ "redirect_uri" ] )
    assert( opts[ "discovery" ] )
    assert( opts[ "client_id" ] )
    assert( opts[ "client_secret" ] )
    assert( opts[ "post_logout_redirect_uri" ] ) 
    assert( opts[ "scope" ] ) 
    return true
end

local function reset_headers()
    local op = ngx.header[ HEADER_OP ]
    local user = ngx.header[ HEADER_USER ]

    if op or user then
        ngx.log( ngx.WARN, "lhauth headers already set[", op, "|", user, "]" )
    end

    ngx.req.clear_header( HEADER_OP )
    ngx.req.clear_header( HEADER_USER )
    ngx.header[ HEADER_OP ] = nil
    ngx.header[ HEADER_USER ] = nil
end

local function handle_res_err( op, res, err )
    ngx.log( ngx.DEBUG, "res: ", cjson_encode( res ), " err: ", cjson_encode( err ) )

    if not err and res then
        local user = res.user.preferred_username
        if not user then
            ngx.log( ngx.ERR, "authe failed err: ", "invalid username" )
            return false
        end
        ngx.log( ngx.DEBUG, "authe success op: ", op, " user: ", user )
        ngx.req.set_header( HEADER_OP, op )
        ngx.req.set_header( HEADER_USER, res.user.preferred_username )
        ngx.header[ HEADER_OP ] = op
        ngx.header[ HEADER_USER ] = user
        return true
    else
        ngx.log( ngx.ERR, "authe failed err: ", cjson_encode( err ) )
        return false
    end
end

-- load into opts_by_op the resty.openidc.authenticate opts in 'opts_json_filepath' 
-- for provider 'op'
function lhauth.load_opts( op, opts_json_filepath )
    assert( op )

    local opts_json_file = assert( io.open( opts_json_filepath, "r" ) )
    local opts_json = opts_json_file:read( "*all" )
    opts_json_file:close()

    local opts = cjson_decode( opts_json )
    assert( check_opts( opts ) )

    opts_by_op[ op ] = opts
end

-- TODO - allow for detecting op through req headers when not( op )

-- check if authed: if yes, set headers; if not, force authe through redirect
function lhauth.login( op )
    reset_headers()
    local res, err = resty_openidc_authenticate( opts_by_op[ op ] )
    return handle_res_err( op, res, err )
end

-- check if authed: if yes, set headers; if not, unset headers
function lhauth.check_authenticated( op )
    reset_headers()
    local res, err = resty_openidc_authenticate( opts_by_op[ op ], nil, "pass" )
    return handle_res_err( op, res, err )
end

-- check if authed: if yes, set headers; if not, exit( forbidden )
function lhauth.require_authenticated( op )
    reset_headers()
    local res, err = resty_openidc_authenticate( opts_by_op[ op ], nil, "deny" )
    return handle_res_err( op, res, err )
end

-- logout
function lhauth.logout( op )
    reset_headers()
    local res, err = resty_openidc_authenticate( opts_by_op[ op ], "/logout" )
    if not err and res then
        ngx.log( ngx.DEBUG, "logout successful" )
        return true
    else
        ngx.log( ngx.ERR, "logout failed err: ", cjson_encode( err ) )
        return false
    end
end

return lhauth;
