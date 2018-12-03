#ifndef h2o__http2_ua_id_h
#define h2o__http2_ua_id_h

typedef enum en_useragent_id_t {
    /**
     * H2O-internal identification of the Google Chrome User Agent.
     */
    UA_CHROME = 0,
    /**
    * H2O-internal identification of the Mozilla Firefox User Agent.
    */
    UA_FIREFOX
} useragent_id_t;

/**
 * The employed User Agent mode. Stated differently, the H2O server is 
 * configured to expect all incoming requests to be issued by the 
 * identified User Agent.
 */
extern useragent_id_t H2O_USERAGENT_EXPECTED;

/* inline definitions */

static inline size_t UA_EXPECTED_CHROME(void)
{
    return (H2O_USERAGENT_EXPECTED == UA_CHROME ? 1 : 0);
}

static inline size_t UA_EXPECTED_FIREFOX(void)
{
    return (H2O_USERAGENT_EXPECTED == UA_FIREFOX ? 1 : 0);
}

#endif

