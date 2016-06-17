/*
 * mod_imagereceiver.h
 *
 *  Created on: 2016/06/17
 *      Author: d9magai
 */

#ifndef SRC_MOD_IMAGERECEIVER_H_
#define SRC_MOD_IMAGERECEIVER_H_

/**
 * struct to store AWS STS Credential
 *
 * see http://docs.aws.amazon.com/STS/latest/UsingSTS/Welcome.html
 */
struct Credential
{
    const char *accesskeyid;
    const char *secretaccesskey;
    const char *token;
    const char *sha256secretkey;
};


#endif /* SRC_MOD_IMAGERECEIVER_H_ */
