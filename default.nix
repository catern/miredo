{ pkgs ? (import <nixpkgs> {}) }:

pkgs.miredo.overrideAttrs (_: { src = ./.; })
