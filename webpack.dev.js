const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');

module.exports = env => {
    return {
        mode: 'development',
        entry: {
            app: './src/kmd.js'
        },
        devtool: 'inline-source-map',
        devServer: {
            contentBase: './dist'
        },
        plugins: [
            new CleanWebpackPlugin(['dist']),
            new HtmlWebpackPlugin({
                title: 'KomodoJS',
                template: 'index.html'
            })
        ],
        output: {
            filename: '[name].bundle.js',
            path: path.resolve(__dirname, 'dist')
        }
    }
};