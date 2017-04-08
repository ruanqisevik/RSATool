//
//  CFPSecurity.h
//  CFPSDK
//
//  Created by 阮琦 on 2016/12/21.
//  Copyright © 2016年 UMS. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CFPSecurity : NSObject
+ (void)generateRSAKeyPairsAndSaveInKeyChain;

+ (NSString *)getPublicKeyStringInKeyChain;
+ (NSData *)getPublicKeyDataInKeyChain;
+ (SecKeyRef)getPublicKeyRefInKeyChain;
+ (SecKeyRef)getPublicKeyRefFromDERData: (NSData *)data;
+ (SecKeyRef)getPublicKeyRefFromPEMString: (NSString *)string;

+ (NSString *)getPrivateKeyStringInKeyChain;
+ (NSData *)getPrivateKeyDataInKeyChain;
+ (SecKeyRef)getPrivateKeyRefInKeyChain;


+ (NSString *)signString: (NSString *)string WithKeyRef: (SecKeyRef)key;
+ (NSData *)signData: (NSData *)data WithKeyRef: (SecKeyRef)key;

+ (BOOL)verifySignature: (NSString *)signature WithKeyRef: (SecKeyRef)key WithSourceText: (NSString *)source;

+ (NSString *)encryptString: (NSString *)string WithKeyRef: (SecKeyRef)key;
+ (NSData *)encryptData: (NSData *)data WithKeyRef: (SecKeyRef)key;

+ (NSString *)decryptString: (NSString *)string WithKeyRef: (SecKeyRef)key;
+ (NSData *)decryptData: (NSData *)data WithKeyRef: (SecKeyRef)key;

+ (NSString *)signString: (NSString *)string ;

+ (NSData *)addPublicKeyHeaderWithData: (NSData *)publicKeyBits;
+ (NSData *)stripPublicKeyHeader:(NSData *)keyData;
@end
