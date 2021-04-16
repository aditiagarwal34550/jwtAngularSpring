FROM node:latest as builder
RUN mkdir -p /app
WORKDIR /app
COPY Frontend/ . 
RUN npm install
RUN npm audit fix
RUN npm run build --prod
CMD ["npm", "start"]

FROM nginx:alpine

COPY Frontend/src/nginx/etc/conf.d/default.conf /etc/nginx/conf/default.conf

COPY --from=builder /app/dist/Angular10JwtAuth  /usr/share/nginx/html
