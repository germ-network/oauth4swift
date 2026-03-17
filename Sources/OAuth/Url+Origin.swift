//
//  Url+Origin.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/24/26.
//

import Foundation

extension URL {
	var origin: String {
		get throws {
			var originComponents = URLComponents()
			originComponents.scheme = try scheme.tryUnwrap
			originComponents.host = try host.tryUnwrap
			originComponents.port = nonDefaultHTTPort()
			return try originComponents.string.tryUnwrap
		}
	}

	func nonDefaultHTTPort() -> Int? {
		switch (scheme, port) {
		case ("http", 80): nil
		case ("https", 443): nil
		default: port
		}
	}
}
