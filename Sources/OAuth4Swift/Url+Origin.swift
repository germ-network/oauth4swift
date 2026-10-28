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
			originComponents.scheme = try scheme.unwrapped
			originComponents.host = try host.unwrapped
			originComponents.port = nonDefaultHTTPort()
			return try originComponents.string.unwrapped
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
