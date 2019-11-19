const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');

module.exports = env => {
    return {
        mode: 'production',
        entry: {
            kmdjs: './src/kmd.js'
        }
    }
};