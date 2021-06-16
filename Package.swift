// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "MEWwalletTweetNacl",
  products: [
    .library(
      name: "MEWwalletTweetNacl",
      targets: ["MEWwalletTweetNacl"]),
  ],
  dependencies: [
  ],
  targets: [
    .target(
      name: "MEWwalletCTweetNacl",
      dependencies: [],
      path: "tweetnacl",
      exclude: [
        "tweetnacl/binding.gyp",
        "tweetnacl/nodetweetnacl.cc",
        "tweetnacl/package.json",
        "tweetnacl/test.js",
        "tweetnacl/LICENSE",
        "tweetnacl/README.md",
        "tweetnacl/index.js"
      ],
      publicHeadersPath: "include"
    ),
    .target(
      name: "MEWwalletTweetNacl",
      dependencies: ["MEWwalletCTweetNacl"]),
    .testTarget(
      name: "MEWwalletTweetNaclTests",
      dependencies: ["MEWwalletTweetNacl"]),
  ]
)
