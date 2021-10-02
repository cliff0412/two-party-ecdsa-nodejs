import Ganache from './ganache';

export default async () => {
  const ganache = new Ganache();
  await ganache.start();
  Ganache.ganache = ganache;
};