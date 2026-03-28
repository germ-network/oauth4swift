//
//  HTTPFieldName+DPoP.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/27/26.
//

import Foundation
import HTTPTypes

extension HTTPField.Name {
	public static var dpop: Self? { .init("DPoP") }

	//https://datatracker.ietf.org/doc/html/rfc9449
	public static var authenticationInfo: Self? {
		.init("DPoP-Nonce")
	}
}
