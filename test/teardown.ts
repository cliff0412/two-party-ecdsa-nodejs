import Ganache from './ganache';
export default async () => {
    await Ganache.ganache.close();
};