//
//  Errors.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/18/26.
//

import Foundation
import HTTPTypes

extension OAuth.DPoP {
	enum Errors: LocalizedError {
		case requestInvalid(HTTPRequest)
		case mismatchedArchive
		
		var errorDescription: String? {
			switch self {
			case .requestInvalid: "Request is not valid"
			case .mismatchedArchive: "Mismatched optional state when restoring dpop"
			}
		}
	}
}
