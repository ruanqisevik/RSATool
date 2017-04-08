//
//  CFPSecurity.m
//  CFPSDK
//
//  Created by 阮琦 on 2016/12/21.
//  Copyright © 2016年 UMS. All rights reserved.
//

#import "CFPSecurity.h"
#import "CFPSecKeyWrapper.h"

@implementation CFPSecurity
+ (void)generateRSAKeyPairsAndSaveInKeyChain {
    [[CFPSecKeyWrapper shared] generateKeyPair:2048];
}


+ (NSString *)getPublicKeyStringInKeyChain {
    return [[self getPublicKeyDataInKeyChain] base64EncodedStringWithOptions:0];
}
+ (NSData *)getPublicKeyDataInKeyChain {
    NSData *headlessData = [[CFPSecKeyWrapper shared] getPublicKeyBits];
    return [self addPublicKeyHeaderWithData:headlessData];
}
+ (SecKeyRef)getPublicKeyRefInKeyChain {
    return [[CFPSecKeyWrapper shared] getPublicKeyRef];
}
+ (SecKeyRef)getPublicKeyRefFromDERData: (NSData *)data {
    //a tag to read/write keychain storage
    NSString *tag = @"__server__Pub";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // 先要删掉keychain中以前存的
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // 将public key加入keychain中
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // 取SecKeyRef
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (SecKeyRef)getPublicKeyRefFromPEMString: (NSString *)string {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
    return [self getPublicKeyRefFromDERData:[self stripPublicKeyHeader:data]];
}

//+ (NSString *)getPrivateKeyStringInKeyChain {
//    
//}
//+ (NSData *)getPrivateKeyDataInKeyChain {
//
//}
+ (SecKeyRef)getPrivateKeyRefInKeyChain {
    return [[CFPSecKeyWrapper shared] getPrivateKeyRef];
}

+ (NSString *)signString: (NSString *)string WithKeyRef: (SecKeyRef)key {
    NSData *plainData = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self signData:plainData WithKeyRef:key];
}

+ (NSData *)signData: (NSData *)data WithKeyRef: (SecKeyRef)key {
    
    if (key == NULL) {
        return @"";
    }
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA1([data bytes], (CC_LONG)[data length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(key,
                  kSecPaddingPKCS1SHA1,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return [signedHash base64EncodedStringWithOptions:0];
}

+ (BOOL)verifySignature: (NSString *)signature WithKeyRef: (SecKeyRef)key WithSourceText: (NSString *)source {
    NSData *sigData = [[NSData alloc]initWithBase64EncodedString:signature options:0];
    NSData *originData = [source dataUsingEncoding:NSUTF8StringEncoding];
    return [[CFPSecKeyWrapper shared] verifySignature: originData secKeyRef:key signature:sigData];
}

+ (NSString *)encryptString: (NSString *)string WithKeyRef: (SecKeyRef)key {
    return [[self encryptData:[string dataUsingEncoding:NSUTF8StringEncoding] WithKeyRef:key] base64EncodedStringWithOptions:0];
}
+ (NSData *)encryptData: (NSData *)data WithKeyRef: (SecKeyRef)key {
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
    for (int i=0; i<blockCount; i++) {
        NSInteger bufferSize = MIN(blockSize,[data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(key, kSecPaddingPKCS1, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
        if (status == noErr){
            NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
        }else{
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer){
        free(cipherBuffer);
    }
    return encryptedData;
}

+ (NSString *)decryptString: (NSString *)string WithKeyRef: (SecKeyRef)key {
    return [[NSString alloc]initWithData:[self decryptData:[[NSData alloc] initWithBase64EncodedString:string options:0] WithKeyRef:key] encoding:NSUTF8StringEncoding];
}
+ (NSData *)decryptData: (NSData *)data WithKeyRef: (SecKeyRef)key {
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    if (key == NULL) {
        NSLog(@"decrypt data with keyRef, keyRef is Null");
        return nil;
    }
    size_t block_size = SecKeyGetBlockSize(key) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(key,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    free(outbuf);
    return ret;
}


+ (NSString *)signString: (NSString *)string {
    return [self signString:string WithKeyRef:[self getPrivateKeyRefInKeyChain]];
}

#pragma mark - Tools Methods

static const unsigned char _encodedRSAEncryptionOID[15] = {
    
    /* Sequence of length 0xd made up of OID followed by NULL */
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    
};

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {         buf[i - j] = length & 0xFF;         length = length >> 8;
    }
    
    return i + 1;
}

+ (NSData *)addPublicKeyHeaderWithData: (NSData *)publicKeyBits {
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (([publicKeyBits length] + 1) / 256 ) + 2 ;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [publicKeyBits length];
    
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    // Now translate the result to a Base64 string
    NSData *pub = [[NSData alloc]initWithBytes:[encKey bytes] length:[encKey length]];
    
    return pub;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)keyData {
    // Skip ASN.1 public key header
    if (keyData == nil) return(nil);
    
    unsigned long len = [keyData length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[keyData bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

@end
