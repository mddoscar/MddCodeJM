//
//  NSString+AES.h
//  AES
//
//  Created by xiaobin liu on 16/2/24.
//  Copyright © 2016年 Sky. All rights reserved.
//

#import <Foundation/Foundation.h>



@interface NSString (AES)


/**
 *  AES加密
 *
 *  @param oriData 加密数据
 *  @param key     加密密钥
 *
 *  @return 加密后的字符串
 */
+(NSString *)encryptString:(NSString *)oriData Key:(NSString *)key;



/**
 *  AES解密
 *
 *  @param decData 解密数据
 *  @param key     解密密钥
 *
 *  @return 解密后的字符串
 */
+ (NSString *)decryptString:(NSString *)decData  Key:(NSString *)key;

@end
