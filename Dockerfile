FROM node:24-alpine
WORKDIR /app
COPY server.js index.html ./
RUN mkdir /data && chown node:node /data
ENV PORT=3000 DB=/data/groceries.db
USER node
VOLUME /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/health >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
