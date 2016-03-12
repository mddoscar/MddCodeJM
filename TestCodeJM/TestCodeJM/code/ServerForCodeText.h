//
//  ServerForCodeText.h
//  TestCodeJM
//
//  Created by szalarm on 16/2/29.
//  Copyright © 2016年 szalarm. All rights reserved.
//

#import <Foundation/Foundation.h>

/*
 加解密服务类,依赖
<GTMBase64.h>
 //aes封装
<NSString+AES.h>
 可以单独使用
 */
@interface ServerForCodeText : NSObject
#pragma mark public
//base64
+(NSString *) EncodeWithBase64:(NSString *) pRawStr;
+(NSString *) DecodeWithBase64:(NSString *) pBase64Str;
//md5
+(NSString*) EncodeMd5FromString:(NSString *)pRawString;
//aes
+(NSData*)EncodeWithAES256tWithKey:(NSString*)key mFromString:(NSString *)pStr;
+(NSData*)DecodeWithAES256DecryptWithKey:(NSString*)key mFromString:(NSString *)pStr;
/**
 *  AES加密
 *
 *  @param oriData 加密数据
 *  @param key     加密密钥
 *
 *  @return 加密后的字符串
 */
+(NSString *)EncodeWithAESFromString:(NSString *)pOriData Key:(NSString *)pkey;
/**
 *  AES解密
 *
 *  @param decData 解密数据
 *
 *  @return 解密后的字符串
 */
+ (NSString *)DecodeWithAESFromString:(NSString *)pDecData  Key:(NSString *)pkey;
+(NSString *)EncodeWithAESDefKeyFromString:(NSString *)pOriData;
/**
 *  AES解密
 *
 *  @param decData 解密数据
 *
 *  @return 解密后的字符串
 */
+ (NSString *)DecodeWithAESDefKeyFromString:(NSString *)pDecData;//默认key
+(NSString*) DefPrivateKey;
//替换数值
+(NSData *)replaceNoUtf8:(NSData *)data;


@end
