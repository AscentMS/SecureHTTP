#import "CordovaHttpPlugin.h"
#import "CDVFile.h"
#import "TextResponseSerializer.h"
#import "HttpManager.h"

@interface CordovaHttpPlugin()

- (void)setRequestHeaders:(NSDictionary*)headers;
- (NSHTTPURLResponse*)httpResponseFromTask:(NSURLSessionTask*)task;
- (NSNumber*)statusCodeFromTask:(NSURLSessionTask*)task;
- (NSDictionary*)headersFromTask:(NSURLSessionTask*)task;
- (id)errorBodyFromError:(NSError*)error;
- (NSSet*)pinnedCertificatesFromMainBundle;

@end

@implementation CordovaHttpPlugin {
    AFHTTPRequestSerializer *requestSerializer;
}

- (void)pluginInitialize {
    requestSerializer = [AFHTTPRequestSerializer serializer];
}

- (void)setRequestHeaders:(NSDictionary*)headers {
    [requestSerializer.HTTPRequestHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [[HttpManager sharedClient].requestSerializer setValue:obj forHTTPHeaderField:key];
    }];
    [headers enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [[HttpManager sharedClient].requestSerializer setValue:obj forHTTPHeaderField:key];
    }];
}

- (NSHTTPURLResponse*)httpResponseFromTask:(NSURLSessionTask*)task {
    if (task && [task.response isKindOfClass:[NSHTTPURLResponse class]]) {
        return (NSHTTPURLResponse*)task.response;
    }
    return nil;
}

- (NSNumber*)statusCodeFromTask:(NSURLSessionTask*)task {
    NSHTTPURLResponse *response = [self httpResponseFromTask:task];
    return [NSNumber numberWithInteger:response ? response.statusCode : 0];
}

- (NSDictionary*)headersFromTask:(NSURLSessionTask*)task {
    NSHTTPURLResponse *response = [self httpResponseFromTask:task];
    return response ? response.allHeaderFields : @{};
}

- (id)errorBodyFromError:(NSError*)error {
    NSData *responseData = error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey];
    if (![responseData isKindOfClass:[NSData class]] || responseData.length == 0) {
        return nil;
    }

    NSString *responseText = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    if (responseText.length > 0) {
        return responseText;
    }

    return nil;
}

- (NSSet*)pinnedCertificatesFromMainBundle {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSMutableSet *pinnedCertificates = [NSMutableSet setWithSet:[AFSecurityPolicy certificatesInBundle:mainBundle]];
    NSArray *wwwCertificatePaths = [mainBundle pathsForResourcesOfType:@"cer" inDirectory:@"www/certificates"];

    for (NSString *certificatePath in wwwCertificatePaths) {
        NSData *certificateData = [NSData dataWithContentsOfFile:certificatePath];
        if (certificateData) {
            [pinnedCertificates addObject:certificateData];
        }
    }

    return [NSSet setWithSet:pinnedCertificates];
}

- (void)useBasicAuth:(CDVInvokedUrlCommand*)command {
    NSString *username = [command.arguments objectAtIndex:0];
    NSString *password = [command.arguments objectAtIndex:1];
    
    [requestSerializer setAuthorizationHeaderFieldWithUsername:username password:password];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)setHeader:(CDVInvokedUrlCommand*)command {
	NSString *header = [command.arguments objectAtIndex:0];
    NSString *value = [command.arguments objectAtIndex:1];
    
    [requestSerializer setValue:value forHTTPHeaderField: header];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)enableSSLPinning:(CDVInvokedUrlCommand*)command {
	bool enable = [[command.arguments objectAtIndex:0] boolValue];

    if (enable) {
        NSSet *pinnedCertificates = [self pinnedCertificatesFromMainBundle];
        [HttpManager sharedClient].securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate withPinnedCertificates:pinnedCertificates];
    } else {
        [HttpManager sharedClient].securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    }
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)acceptAllCerts:(CDVInvokedUrlCommand*)command {
	CDVPluginResult* pluginResult = nil;
	bool allow = [[command.arguments objectAtIndex:0] boolValue];
    
    [HttpManager sharedClient].securityPolicy.allowInvalidCertificates = allow;
    
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)post:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
	NSString *url = [command.arguments objectAtIndex:0];
	NSDictionary *parameters = [command.arguments objectAtIndex:1];
	NSDictionary *headers = [command.arguments objectAtIndex:2];

	CordovaHttpPlugin* __weak weakSelf = self;

	manager.requestSerializer = [AFJSONRequestSerializer serializer];
	manager.responseSerializer = [TextResponseSerializer serializer];

	[self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }
   
	[manager POST:url parameters:parameters headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		[dictionary setObject:responseObject forKey:@"data"];
		[dictionary setObject:[self headersFromTask:task] forKey:@"headers"];
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	} failure:^(NSURLSessionDataTask *task, NSError *error) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		@try {
			[dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
			[dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	}];
}

- (void)get:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
	NSString *url = [command.arguments objectAtIndex:0];
	NSDictionary *parameters = [command.arguments objectAtIndex:1];
	NSDictionary *headers = [command.arguments objectAtIndex:2];

	CordovaHttpPlugin* __weak weakSelf = self;

	manager.requestSerializer = [AFHTTPRequestSerializer serializer];
	manager.responseSerializer = [TextResponseSerializer serializer];

	[self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }
   
	[manager GET:url parameters:parameters headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		[dictionary setObject:responseObject forKey:@"data"];
		[dictionary setObject:[self headersFromTask:task] forKey:@"headers"];
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	} failure:^(NSURLSessionDataTask *task, NSError *error) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		@try {
			[dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
			[dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	}];
}

- (void)put:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
	NSString *url = [command.arguments objectAtIndex:0];
	NSDictionary *parameters = [command.arguments objectAtIndex:1];
	NSDictionary *headers = [command.arguments objectAtIndex:2];
   
	CordovaHttpPlugin* __weak weakSelf = self;

	manager.requestSerializer = [AFJSONRequestSerializer serializer];
	manager.responseSerializer = [TextResponseSerializer serializer];

	[self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }

	[manager PUT:url parameters:parameters headers:nil success:^(NSURLSessionDataTask *task, id responseObject) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		[dictionary setObject:responseObject forKey:@"data"];
		[dictionary setObject:[self headersFromTask:task] forKey:@"headers"];
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	} failure:^(NSURLSessionDataTask *task, NSError *error) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		@try {
			[dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
			[dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	}];
}

- (void)delete:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
	NSString *url = [command.arguments objectAtIndex:0];
	NSDictionary *parameters = [command.arguments objectAtIndex:1];
	NSDictionary *headers = [command.arguments objectAtIndex:2];
   
	CordovaHttpPlugin* __weak weakSelf = self;

	manager.requestSerializer = [AFJSONRequestSerializer serializer];
	manager.responseSerializer = [TextResponseSerializer serializer];

	manager.requestSerializer.HTTPMethodsEncodingParametersInURI = [NSSet setWithObjects:@"GET", @"HEAD", nil];

	[self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }

	[manager DELETE:url parameters:parameters headers:nil success:^(NSURLSessionDataTask *task, id responseObject) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		[dictionary setObject:responseObject forKey:@"data"];
		[dictionary setObject:[self headersFromTask:task] forKey:@"headers"];
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	} failure:^(NSURLSessionDataTask *task, NSError *error) {
		NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
		[dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		@try {
			[dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
			[dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
		[weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	}];
}

- (void)uploadFile:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    NSString *filePath = [command.arguments objectAtIndex: 3];
    NSString *name = [command.arguments objectAtIndex: 4];
    
	CordovaHttpPlugin* __weak weakSelf = self;

    NSString *filePathFormatted = [filePath stringByReplacingOccurrencesOfString:@"file:///" withString:@""];
    
    NSURL *fileURL = [NSURL fileURLWithPath: filePathFormatted];

	manager.requestSerializer = [AFHTTPRequestSerializer serializer];
	manager.responseSerializer = [TextResponseSerializer serializer];

	[self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }

    [manager POST:url parameters:parameters headers:nil constructingBodyWithBlock:^(id<AFMultipartFormData> formData) {
        NSError *error;
        [formData appendPartWithFileURL:fileURL name:name error:&error];
        if (error) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            [dictionary setObject:@"Could not add image to post body." forKey:@"error"];
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
    } progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
		[dictionary setObject:responseObject forKey:@"data"];
		[dictionary setObject:[self headersFromTask:task] forKey:@"headers"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
        @try {
           [dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
           [dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}


- (void)downloadFile:(CDVInvokedUrlCommand*)command {
	HttpManager *manager = [HttpManager sharedClient];
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    NSString *filePath = [command.arguments objectAtIndex: 3];
   
	CordovaHttpPlugin* __weak weakSelf = self;

	manager.requestSerializer = [AFHTTPRequestSerializer serializer];
	manager.responseSerializer = [AFHTTPResponseSerializer serializer];

    [self setRequestHeaders: headers];

	// Sanitize parameters before AFNetworking call
    if ([parameters isKindOfClass:[NSNull class]] || parameters == nil) {
		// If NSBull is passed, make it nil
        parameters = nil;
    } else if ([parameters count] == 0) {
		// If an object is passed with no entries, make it nil
        parameters = nil;
    }
    
    [manager GET:url parameters:parameters headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        /*
         *
         * Licensed to the Apache Software Foundation (ASF) under one
         * or more contributor license agreements.  See the NOTICE file
         * distributed with this work for additional information
         * regarding copyright ownership.  The ASF licenses this file
         * to you under the Apache License, Version 2.0 (the
         * "License"); you may not use this file except in compliance
         * with the License.  You may obtain a copy of the License at
         *
         *   http://www.apache.org/licenses/LICENSE-2.0
         *
         * Unless required by applicable law or agreed to in writing,
         * software distributed under the License is distributed on an
         * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
         * KIND, either express or implied.  See the License for the
         * specific language governing permissions and limitations
         * under the License.
         *
         * Modified by Andrew Stephan for Sync OnSet
         *
        */
        // Download response is okay; begin streaming output to file
        NSString* parentPath = [filePath stringByDeletingLastPathComponent];
        
        // create parent directories if needed
        NSError *error;
        if ([[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error] == NO) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            if (error) {
                [dictionary setObject:[NSString stringWithFormat:@"Could not create path to save downloaded file: %@", [error localizedDescription]] forKey:@"error"];
            } else {
                [dictionary setObject:@"Could not create path to save downloaded file" forKey:@"error"];
            }
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
        NSData *data = (NSData *)responseObject;
        if (![data writeToFile:filePath atomically:YES]) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            [dictionary setObject:@"Could not write the data to the given filePath." forKey:@"error"];
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
   
        CDVFile *file = [[CDVFile alloc] init];
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
        [dictionary setObject:[file getDirectoryEntry:filePath isDirectory:NO] forKey:@"file"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [dictionary setObject:[self statusCodeFromTask:task] forKey:@"status"];
        @try {
           [dictionary setObject:[self errorBodyFromError:error] forKey:@"error"];
		}
		@catch (NSException *exception) {
           [dictionary setObject:[error localizedDescription] forKey:@"error"];
		}
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

@end
