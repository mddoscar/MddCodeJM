//
//  ViewController.h
//  TestCodeJM
//
//  Created by szalarm on 16/2/29.
//  Copyright © 2016年 szalarm. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController


#pragma mark ib
@property (weak, nonatomic) IBOutlet UITextField *mUiInputTextField;
@property (weak, nonatomic) IBOutlet UITextField *mUiOutPutTextField;
- (IBAction)dobase64EnCode:(id)sender;
- (IBAction)dobase64DisCode:(id)sender;
- (IBAction)doAesEnCode:(id)sender;
- (IBAction)doAesDeCode:(id)sender;
- (IBAction)doMd5Encode:(id)sender;



@end

