#! /usr/bin/env bash

echo "Starting Nginx-Njs Docker container ..."

# Note -P will auto assign port mapping - random port
# docker run -d --name nginx_njs -p 8080:80 -v $PWD/nginx.conf:/etc/nginx/nginx.conf -v $PWD/conf.d:/etc/nginx/conf.d nginx:latest nginx -g 'daemon off;'

docker run -d --name nginx_njs -p 8080:80 -v $PWD/nginx.conf:/etc/nginx/nginx.conf -v $PWD/conf.d:/etc/nginx/conf.d nginx:1.20.1 nginx -g 'daemon off;'