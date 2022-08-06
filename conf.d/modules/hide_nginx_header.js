function maskHeaderOut(r) {
    delete r.headersOut['Server'];
    delete r.headersOut['Server'];
    r.headersOut['server'] = '********'
    r.headersOut['Server'] = '*****'
    
}
export default {maskHeaderOut}