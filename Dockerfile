FROM node:9

COPY . /app
WORKDIR /app

RUN echo '{ "allow_root": true }' > /root/.bowerrc && npm i && npx bower install


