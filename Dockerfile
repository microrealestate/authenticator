FROM node:12-slim AS base
WORKDIR /usr/app
RUN npm set progress=false && \
    npm config set depth 0
COPY . .

FROM base as dependencies
RUN npm install --silent --only=production

FROM base AS release
RUN npm install forever -g --silent
COPY --from=dependencies /usr/app .
CMD forever ./index.js