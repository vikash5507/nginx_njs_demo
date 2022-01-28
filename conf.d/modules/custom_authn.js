function makeAuthNRequest(r) {

    var authn_internal_url = "/authenticate";
    var arm_internal_url = "/arm-backend";
    var reqStartTime = r.variables.msec;

    //Before making subrequest calculate X-CORRELATION-ID, X-REQ-ID, X-DEPTH
    var crId = correlation_id(r);
    var reqId = req_id(r);
    var xDepth = 1;
    var body;

    r.variables['x_correlation_id'] = crId;
    r.variables['x_req_id'] = reqId;
    r.variables['x_depth'] = xDepth;

    var isAuthNEnabled = r.variables.authn_enable.toLowerCase();

    //CAL -> Log INCOMING MAIN Request
    ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"REUEST\" RTY=\"IN\"" + ` MTHD=\"${r.method}\" U=\"${r.uri}\" H=${headers_to_string(r.headersIn)} ${cal_log_handler(crId, reqId, xDepth)}`); 

    if (isAuthNEnabled) {
        /**
         * AuthN is Enabled
         * 1. Make Subrequest call to AuthN and do error handling if not 200 else make subrequest to ARM
         */
        ngx.log(ngx.INFO, "AuthN is enabled!!");

        r.subrequest(authn_internal_url, {
            args: r.variables.args,
            method: r.method,
            body: r.requestText
        }, function (authn_res) {
            ngx.log(ngx.INFO, "AUTHN response status: " + authn_res.status);

            //CAL -> Log INCOMING AUTHN Request
            ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"REUEST\" RTY=\"OUT\"" + ` MTHD=\"${r.method}\" U=\"authn${r.variables.request_uri}\" T=${r.variables.host}:${r.variables.server_port} US=${r.variables.scheme}://${authn_res.variables.upstream_addr} H=${headers_to_string(authn_res.headersIn)} ${cal_log_handler(crId, reqId, xDepth)}`); 

            //CAL -> Log OUTGOING AUTHN Response
            ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"RESPONSE\" RTY=\"OUT\"" + ` MTHD=\"${r.method}\" U=\"authn${r.variables.request_uri}\" S=${authn_res.status} D=${authn_res.variables.upstream_response_time} T=${r.variables.host}:${r.variables.server_port} US=${r.variables.scheme}://${authn_res.variables.upstream_addr} H=${headers_to_string(authn_res.headersOut)} ${cal_log_handler(crId, reqId, xDepth)}`);

            if (authn_res.status != 200) {
                ngx.log(ngx.ERR, "Call to AuthN Failed with " + authn_res.status);

                r.return(500, authn_res.responseBody);
            } else {
                if (authn_res.headersOut['X-AUTHN-APP-ID']) {
                    var app_id_header = authn_res.headersOut['X-AUTHN-APP-ID'];
                    r.variables['x_authn_app_id'] = app_id_header; //update global var to add this header in arm request
                } else {
                    ngx.log(ngx.ERR, "X-AUTHN-APP-ID header is not present in AuthN response");
                    r.return(500, authn_res.responseBody);
                    return;
                }

                //Now make subrequest to ARM internal
                xDepth += 1
                r.variables["x_depth"] = xDepth;
                
                /** 
                 * ARM redirect without subrequest
                */
               //r.internalRedirect('/arm-backend');


                r.subrequest(arm_internal_url, {
                    args: r.variables.args,
                    method: r.method,
                    body: r.requestText
                }, function (arm_res) {
                    ngx.log(ngx.INFO, "ARM response status: " + arm_res.status);

                    //CAL -> Log INCOMING ARM Request
                    ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"REQUEST\" RTY=\"OUT\"" + ` MTHD=\"${r.method}\" U=\"arm${r.variables.request_uri}\" T=${r.variables.host}:${r.variables.server_port} US=${r.variables.scheme}://${arm_res.variables.upstream_addr} H=${headers_to_string(arm_res.headersIn)} ${cal_log_handler(crId, reqId, xDepth)}`); 

                    //CAL -> Log OUTGOING ARM Response
                    ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"RESPONSE\" RTY=\"OUT\"" + ` MTHD=\"${r.method}\" U=\"arm${r.variables.request_uri}\" S=${arm_res.status} D=${arm_res.variables.upstream_response_time} T=${r.variables.host}:${r.variables.server_port} US=${r.variables.scheme}://${arm_res.variables.upstream_addr} H=${headers_to_string(arm_res.headersOut)} ${cal_log_handler(crId, reqId, xDepth)}`);


                    //TODO FIX to get main request respone and its header -> CAL -> Log OUTGOING Nginx Main Response
                    var currTime = r.variables.msec;
                    var responseTimeMS = currTime - reqStartTime;

                    ngx.log(ngx.INFO, "LOG=\"HTTPEvent\" TY=\"RESPONSE\" RTY=\"IN\"" + ` MTHD=\"${r.method}\" U=\"${r.uri}\" S=${arm_res.status} D=${responseTimeMS} H=${headers_to_string(arm_res.headersOut)} ${cal_log_handler(crId, reqId, xDepth)}`);
                    
                    r.return(arm_res.status, arm_res.responseBody);
                    //return;
                })
            }
        })

        
    } else {
        /**
         * AuthN is disabled:
         * 1. No Need to make subrequest to AuthN
         * 2. Directly makr subrequest call to ARM proxy (need to inject some headers OtherWise just redirect)
         */
        ngx.log(ngx.INFO, "AuthN is disabled!!");
        
        r.subrequest(arm_internal_url, {
            args: r.variables.args,
            method: r.method,
            body: r.requestText
        }, function (arm_res) {
            ngx.log(ngx.INFO, "ARM response status: " + arm_res.status);
        })
    }
    
}

function correlation_id(r) {
    //CRID format - TimeSeconds_TimeMilliSeconds_RandomNumber_ObfuscatedHostname_AppName
    var msec = String(parseFloat(r.variables.msec).toFixed(3)).replace('.','_');
    var random = parseInt('0x' + r.variables.request_id.substring(0, 8));

    var obfuscated_hostname = '';
    var hostname = r.variables.hostname;

    for (var i = 0; i < hostname.length; i++) {
        var current_char = hostname[i];
        var next_char = '';
        if (i+1 < hostname.length) {
            next_char = hostname[i+1];
        }

        if ((current_char >= '0' && current_char <= '9') || (next_char >= '0' && next_char <= '9')) {
            obfuscated_hostname += r.variables.hostname[i];
        }
    }

    var app_name = r.variables.cal_app_name || "NONE";
    var finalCRId = msec + '_' + random + '_' + obfuscated_hostname + '_' + app_name;

    return finalCRId;
}

function req_id(r) {
    return String(parseFloat(r.variables.msec).toFixed(3)).replace('.', '');
}

function headers_to_string(headersIn) {
    var headersInStr = '\"';

    for (var key in headersIn) {
        var value = headersIn[key];
        headersInStr += key + ": " + value + "; ";
    }

    headersInStr += '\"';

    return headersInStr;
}

function cal_log_handler(crId, reqId, xDepth) {
    return `CR=\"${crId}\" RE=\"${reqId}\" DE=\"${xDepth}\"`;
}

export default {makeAuthNRequest}