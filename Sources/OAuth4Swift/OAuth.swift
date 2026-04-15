//
//  OAuth.swift
//  OAuth
//
//  Created by Mark @ Germ on 4/15/26.
//

import Foundation

public enum OAuth {}

//Abstraction of ASWebAuthentication or AuthTabIntent
public typealias UserAuthenticator = @Sendable (URL, String) async throws -> URL
