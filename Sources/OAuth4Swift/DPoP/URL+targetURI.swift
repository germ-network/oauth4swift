//
//  URL+targetURI.swift
//  OAuth
//
//  Created by Emelia Smith on 3/7/26.
//

import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

extension URL {
	var targetURI: URL? {
		guard
			let host = self.host,
			let scheme = self.scheme
		else {
			return nil
		}

		var originComponents = URLComponents()
		originComponents.scheme = scheme
		originComponents.host = host
		originComponents.path = self.relativePath

		originComponents.port = nonDefaultHTTPort()

		return originComponents.url
	}
}
