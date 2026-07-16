// EndpointSecurity entitlement probe.
//
// Proves whether a self-signed binary carrying the restricted ES entitlement
// (com.apple.developer.endpoint-security.client) is honored on this machine —
// i.e. whether a SIP/AMFI-relaxed dev VM can run the leash ES extension without
// an Apple-granted entitlement. Throwaway: creates one ES client, prints the
// result code, exits. See mac-leash/devtools/esprobe/run.sh and docs/MACOS-DEV.md.
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>

int main(void) {
    es_client_t *client = NULL;
    es_new_client_result_t r =
        es_new_client(&client, ^(es_client_t *c, const es_message_t *m){});
    printf("es_new_client result = %d\n", r);
    if (client) es_delete_client(client);
    return r;
}
