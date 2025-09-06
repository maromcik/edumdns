FROM nginx:latest
RUN rm /etc/nginx/conf.d/default.conf
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt -subj "/C=SK/ST=./L=./O=./OU=./CN=."
RUN openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
COPY ./nginx.conf /etc/nginx/
COPY ./conf.d/* /etc/nginx/conf.d