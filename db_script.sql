CREATE TABLE ids_attacklogs
(
  id serial NOT NULL,
  attacktype text NOT NULL,
  starttime timestamp with time zone NOT NULL,
  endtime timestamp with time zone NOT NULL,
  destip character varying(20) NOT NULL,
  srcip character varying(20),
  destport integer,
  ps_flowcount integer,
  sf_syncount integer,
  uf_packetcount integer,
  rf_rstcount integer,
  tf_ttlcount integer,
  ff_fincount integer,
  probability integer,
  CONSTRAINT ids_attacklogs_pkey PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE ids_attacklogs
  OWNER TO slawebuser;



CREATE TABLE ids_attackdetails
(
  id serial NOT NULL,
  attack_id integer NOT NULL,
  since timestamp with time zone NOT NULL,
  till timestamp with time zone NOT NULL,
  probability integer,
  sf_syncount integer,
  uf_packetcount integer,
  rf_rstcount integer,
  tf_ttlcount integer,
  ff_fincount integer,
  CONSTRAINT ids_attackdetails_pkey PRIMARY KEY (id),
  CONSTRAINT ids_attackdetails_attack_id_fkey FOREIGN KEY (attack_id)
      REFERENCES ids_attacklogs (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)
WITH (
  OIDS=FALSE
);
ALTER TABLE ids_attackdetails
  OWNER TO slawebuser;

CREATE INDEX ids_attackdetails_attack_id
  ON ids_attackdetails
  USING btree
  (attack_id);
