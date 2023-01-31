FROM rust:latest
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

EXPOSE 1337

CMD [ "uploadly" ]