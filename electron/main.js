'use strict';
// Thin wiring: the logic lives in app-shell.js so it can be tested with a fake `electron`.
const electron = require('electron');
const { startApp } = require('./app-shell');
const { EngineClient } = require('./engine-client');
const { resolveEngine } = require('./engine-path');
const { makeFileApi } = require('./files');

startApp({ electron, EngineClient, resolveEngine, makeFileApi, rootDir: __dirname,
  resourcesPath: process.resourcesPath });
